#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import logging
import struct
import errno
import random

from shadowsocks import encrypt, eventloop, lru_cache, common, shell
from shadowsocks.common import parse_header, pack_addr, onetimeauth_verify, \
    onetimeauth_gen, ONETIMEAUTH_BYTES, ADDRTYPE_AUTH


BUF_SIZE = 65536


def client_key(source_addr, server_af):
    # notice this is server af, not dest af
    return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)


class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._config = config
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = common.to_bytes(config['password'])
        self._method = config['method']
        self._timeout = config['timeout']
        self._ota_enable = config.get('one_time_auth', False)
        self._ota_enable_session = self._ota_enable
        self._is_local = is_local
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])
        self._dns_cache = lru_cache.LRUCache(timeout=300)
        self._eventloop = None
        self._closed = False
        self._sockets = set()
        self._forbidden_iplist = config.get('forbidden_ip')
        #socket.SOCK_DGRAM sock_dgram 是无保障的面向消息的socket ， 主要用于在网络上发广播信息。基于UDP的数据报式socket通信
        #socket.SOCK_STREAM 是有保障的(即能保证数据正确传送到对方)面向连接的SOCKET,基于TCP的流式socket通信
        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)

        if len(addrs) == 0:
            raise Exception("UDP can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    #如果config.json中配置了多个ss server则随机选择一个，需要实现选服务器算法
    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        if type(server) == list:
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass
    #负责将来自客户端的数据转发给服务器
    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        key = None
        iv = None
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        if self._is_local:
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            #      ~~~~~~~~
            frag = common.ord(data[2])  #shadowsocks中FRAG就使用0
            if frag != 0:
                logging.warn('UDP drop a message since frag is not 0')
                return
            else:
                # +------+----------+----------+----------+
                # | ATYP | DST.ADDR | DST.PORT |   DATA   |
                # +------+----------+----------+----------+
                data = data[3:]
        else:
            data, key, iv = encrypt.dencrypt_all(self._password,
                                                 self._method,
                                                 data)
            # decrypt data
            if not data:
                logging.debug(
                    'UDP handle_server: data is empty after decrypt'
                )
                return
        header_result = parse_header(data)
        if header_result is None:
            return

        # +------+----------+----------+----------+
        # | ATYP | DST.ADDR | DST.PORT |   DATA   |
        # +------+----------+----------+----------+
        # .                            .
        # |<----- header_length ------>|
        addrtype, dest_addr, dest_port, header_length = header_result

        # 如果是sslocal，则需要查找的是ssserver的地址及端口
        # 如果是ssserver，则需要获取的是目标服务器的地址及端口
        if self._is_local:
            # ssserver 地址和端口
            server_addr, server_port = self._get_a_server()
        else:
            # 「目标服务器」地址和端口
            server_addr, server_port = dest_addr, dest_port
            # spec https://shadowsocks.org/en/spec/one-time-auth.html
            self._ota_enable_session = addrtype & ADDRTYPE_AUTH
            if self._ota_enable and not self._ota_enable_session:
                logging.warn('client one time auth is required')
                return
            if self._ota_enable_session:
                if len(data) < header_length + ONETIMEAUTH_BYTES:
                    logging.warn('UDP one time auth header is too short')
                    return
                _hash = data[-ONETIMEAUTH_BYTES:]
                data = data[: -ONETIMEAUTH_BYTES]
                _key = iv + key
                if onetimeauth_verify(_hash, data, _key) is False:
                    logging.warn('UDP one time auth fail')
                    return
        # 从缓存中取 server_addr 解析后的地址
        addrs = self._dns_cache.get(server_addr, None)
        # 如果找不到，则解析 server_addr 的地址并存入缓存
        if addrs is None:
            # 注意，getaddrinfo 函数是阻塞的
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if not addrs:
                # drop
                return
            else:
                self._dns_cache[server_addr] = addrs

        af, socktype, proto, canonname, sa = addrs[0]

        # 根据地址、端口、af 生成一个 key，这个 key 与 UDP 套接字一一对应
        key = client_key(r_addr, af)
        client = self._cache.get(key, None)
        if not client:
            # TODO async getaddrinfo
            if self._forbidden_iplist:
                if common.to_str(sa[0]) in self._forbidden_iplist:
                    logging.debug('IP %s is in forbidden list, drop' %
                                  common.to_str(sa[0]))
                    # drop
                    return
            # 创建 UDP 套接字
            client = socket.socket(af, socktype, proto)
            client.setblocking(False)
            self._cache[key] = client
            # 将套接字与其地址关联起来，`_handle_client` 会用到
            self._client_fd_to_server_addr[client.fileno()] = r_addr
            # 将套接字关联的文件描述符加入 `self._sockets` 中，`handle_event` 会用到
            self._sockets.add(client.fileno())
            # 将套接字加入事件循环，
            self._eventloop.add(client, eventloop.POLL_IN, self)
        # 如果是 sslocal，那么需要将数据加密
        if self._is_local:
            key, iv, m = encrypt.gen_key_iv(self._password, self._method)
            # spec https://shadowsocks.org/en/spec/one-time-auth.html
            if self._ota_enable_session:
                data = self._ota_chunk_data_gen(key, iv, data)
            data = encrypt.encrypt_all_m(key, iv, m, self._method, data)
            if not data:
                return
        # 如果是 ssserver，在将接收到的数据发送给目标服务器之前，
        # 需要解密并且去掉头部，解密在上面已经完成了
        else:
            # +------+----------+----------+----------+
            # | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +------+----------+----------+----------+
            #
            data = data[header_length:]
        if not data:
            return
        # - 对于 sslocal 而言，将加密后的数据发送给 ssserver，数据格式如下：
        #
        #    +------+----------+----------+----------+
        #    | ATYP | DST.ADDR | DST.PORT |   DATA   |
        #    +------+----------+----------+----------+
        #
        # - 对于 ssserver 而言，将解密后的数据发送给目标服务器（只剩 `DATA` 部分了）
        try:
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                shell.print_exception(e)

    # 处理服务器返回给客户端的数据并转发给客户端
    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        # ssserver
        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            # |    pack_addr    |   pack   |
            # .                 .          .
            # +------+----------+----------+----------+
            # | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +------+----------+----------+----------+
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            # `1` 表示加密
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return
        #sslocal
        else:
            # `0` 表示解密
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            addrtype, dest_addr, dest_port, header_length = header_result

            # \x00\x00\x00
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            #             .                                       .
            #             |<--------------- data ---------------->|
            response = b'\x00\x00\x00' + data
        # 这里的 sock 就是 _handle_server 中的 client
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        # 通过 _server_socket 将数据发送到 client 对应的地址
        if client_addr:
            self._server_socket.sendto(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def _ota_chunk_data_gen(self, key, iv, data):
        data = common.chr(common.ord(data[0]) | ADDRTYPE_AUTH) + data[1:]
        key = iv + key
        return data + onetimeauth_gen(data, key)

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        loop.add_periodic(self.handle_periodic)

    def handle_event(self, sock, fd, event):
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                logging.error('UDP server_socket err')
            self._handle_server()
        elif sock and (fd in self._sockets):
            if event & eventloop.POLL_ERR:
                logging.error('UDP client_socket err')
            self._handle_client(sock)

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._server_socket.close()
                self._server_socket = None
                for sock in self._sockets:
                    sock.close()
                logging.info('closed UDP port %d', self._listen_port)
        self._cache.sweep()
        self._client_fd_to_server_addr.sweep()
        self._dns_cache.sweep()

    def close(self, next_tick=False):
        logging.debug('UDP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for client in list(self._cache.values()):
                client.close()
