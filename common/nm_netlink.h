/*
 * Copyright © 2016-2018 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#pragma once

#define NETLINK_BUFSIZE 8192

typedef struct netlink_link {
        struct nlmsghdr nlHdr;
        struct ifinfomsg linkInfo;
        char  buf[NETLINK_BUFSIZE];
} netlink_link;

typedef struct netlink_route {
        struct nlmsghdr nlHdr;
        struct rtmsg rtInfo;
        char  buf[NETLINK_BUFSIZE];
} netlink_route;

uint32_t
netlink_add_attr(
    struct nlmsghdr *nlHdr,
    int attrType,
    const void *attrValue,
    int attrLen
);

uint32_t
netlink_add_attr_uint8(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint8_t attrValue
);

uint32_t
netlink_add_attr_uint16(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint16_t attrValue);

uint32_t
netlink_add_attr_uint32(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint32_t attrValue
);

uint32_t
netlink_add_attr_uint64(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint64_t attrValue
);

uint32_t
netlink_add_attr_string(
    struct nlmsghdr *nlHdr,
    int attrType,
    const char *attribute
);

uint32_t
netlink_socket_send_message(
    int sockFd,
    void *nlBuffer,
    ssize_t bufLength
);

uint32_t
socket_recv_message(
    int sockFd,
    void *nlRecvBuffer,
    ssize_t bufLength,
    ssize_t *readSize
);

uint32_t netlink_call(
    int sockFd,
    void *nlSendBuf,
    size_t nlSendbufLen,
    void *nlRecvBuf,
    size_t nlRecvbufLen,
    ssize_t *readSize
);
