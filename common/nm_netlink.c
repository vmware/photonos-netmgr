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

#include "includes.h"

uint32_t
netlink_add_attr(
    struct nlmsghdr *nlHdr,
    int attrType,
    const void *attrValue,
    int attrLen
)
{
    int iLen = RTA_LENGTH(attrLen);
    struct rtattr *rtAttr;

    rtAttr = (struct rtattr *) (((void *) (nlHdr)) + NLMSG_ALIGN((nlHdr)->nlmsg_len));
    rtAttr->rta_type = attrType;
    rtAttr->rta_len = iLen;

    if (attrLen)
    {
        memcpy(RTA_DATA(rtAttr), attrValue, attrLen);
    }

    nlHdr->nlmsg_len = NLMSG_ALIGN(nlHdr->nlmsg_len) + RTA_ALIGN(iLen);

    return 0;
}

uint32_t
netlink_add_attr_uint8(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint8_t attrValue
)
{
    return netlink_add_attr(nlHdr, attrType, &attrValue, sizeof(uint8_t));
}

uint32_t
netlink_add_attr_uint16(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint16_t attrValue
)
{
    return netlink_add_attr(nlHdr, attrType, &attrValue, sizeof(uint16_t));
}

uint32_t
netlink_add_attr_uint32(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint32_t attrValue
)
{
    return netlink_add_attr(nlHdr, attrType, &attrValue, sizeof(uint32_t));
}

uint32_t
netlink_add_attr_uint64(
    struct nlmsghdr *nlHdr,
    int attrType,
    uint64_t attrValue
)
{
    return netlink_add_attr(nlHdr, attrType, &attrValue, sizeof(uint64_t));
}

uint32_t
netlink_add_attr_string(
    struct nlmsghdr *nlHdr,
    int attrType,
    const char *attribute
)
{
    return netlink_add_attr(nlHdr, attrType, attribute, strlen(attribute)+1);
}

uint32_t
netlink_socket_open(
    uint32_t netLinkGroup,
    int *pSockFd
)
{
    _cleanup_(closep) int sockFd = -1;
    struct sockaddr_nl addr = {
                               .nl_family = AF_NETLINK,
                               .nl_pid = getpid(),
                               .nl_groups = netLinkGroup
    };
    uint32_t err = 0;
    int reuseAddr = 1;

    if (!pSockFd)
    {
        err = EINVAL;
    }
    bail_on_error(err);

    sockFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockFd < 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(int)))
    {
        err = errno;
        bail_on_error(err);
    }

    if (fcntl(sockFd, F_SETFL, O_NONBLOCK) == -1)
    {
        err = errno;
        bail_on_error(err);
    }

    if (bind(sockFd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *pSockFd = sockFd;
    sockFd = -1;

error:
    return err;
}

uint32_t
netlink_socket_send_message(
    int sockFd,
    void *nlBuffer,
    ssize_t bufLength
)
{
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov = {
                        .iov_base = nlBuffer,
                        .iov_len = bufLength
    };
    struct msghdr msg = {
                         .msg_name = &nladdr,
                         .msg_namelen = sizeof(nladdr),
                         .msg_iov = &iov,
                         .msg_iovlen = 1,
    };
    uint32_t err = 0;
    int r;

    r = sendmsg(sockFd, &msg, 0);
    if (r < 0)
    {
        err = errno;
        bail_on_error(err);
    }

 error:
    return err;
}

uint32_t
netlink_socket_receive_message(
    int sockFd,
    void *psznlRecvBuffer,
    ssize_t bufLength,
    ssize_t *readSize
)
{
    uint32_t err = 0;
    ssize_t readLen;
    struct sockaddr_nl addr;
    struct iovec iov = {
                        .iov_base       = psznlRecvBuffer,
                        .iov_len        = bufLength,
    };
    struct msghdr msg = {
                         .msg_name       = &addr,
                         .msg_namelen    = sizeof(struct sockaddr_nl),
                         .msg_iov        = &iov,
                         .msg_iovlen     = 1,
                         .msg_control    = NULL,
                         .msg_controllen = 0,
                         .msg_flags      = 0,
    };

    readLen = recvmsg(sockFd, &msg, 0);
    if (readLen == -1)
    {
        err = errno;
        bail_on_error(err);
    }

    if (msg.msg_flags & MSG_TRUNC)
    {
        errno = ENOSPC;
        bail_on_error(err);
    }

    if (msg.msg_namelen != sizeof(struct sockaddr_nl))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    *readSize = readLen;

 error:
    return err;
}

uint32_t netlink_call(
    int sockFd,
    void *nlSendBuf,
    size_t nlSendbufLen,
    void *pszNlRecvBuf,
    size_t nlRecvbufLen,
    ssize_t *readSize
)
{
    struct nlmsghdr *nlHdr = (struct nlmsghdr *) pszNlRecvBuf;
    uint32_t err = 0, msgSeq;
    pid_t pId;
    int r;

    msgSeq = nlHdr->nlmsg_seq = random();
    pId = nlHdr->nlmsg_pid = getpid();

    r = netlink_socket_send_message(sockFd, nlSendBuf, nlSendbufLen);
    if (r != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    r = netlink_socket_receive_message(sockFd, pszNlRecvBuf, nlRecvbufLen, readSize);
    if (r != 0)
    {
        err = errno;
        bail_on_error(err);
    }

     nlHdr = (struct nlmsghdr *) pszNlRecvBuf;
     if ((NLMSG_OK(nlHdr, readSize) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
     {
         err = errno;
         bail_on_error(err);
     }

     if ((nlHdr->nlmsg_seq != msgSeq) || (nlHdr->nlmsg_pid != pId))
     {
         err = errno;
         bail_on_error(err);
     }

 error:
    return err;
}
