/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the ?~@~\License?~@~]); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ?~@~\AS IS?~@~] BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "includes.h"

uint32_t
is_ipv4_addr(const char *pszIpAddr)
{
    struct sockaddr_in sa;
    return (inet_pton(AF_INET, pszIpAddr, &(sa.sin_addr)) != 0);
}

uint32_t
is_ipv6_addr(const char *pszIpAddr)
{
    struct sockaddr_in6 sa;
    return (inet_pton(AF_INET6, pszIpAddr, &(sa.sin6_addr)) != 0);
}

uint32_t
flush_interface_ipaddr(
    const char *pszInterfaceName
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr;
    struct sockaddr_in sin;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }
    // TODO: Flush IPV6 Address

    memset(&sin, 0, sizeof(struct sockaddr_in));
    inet_aton("0.0.0.0", &sin.sin_addr);
    sin.sin_family = AF_INET;
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr_in));

    err = ioctl(sockFd, SIOCSIFADDR, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
get_prefix_from_netmask(
    struct sockaddr *pSockAddr,
    uint8_t *pPrefix
)
{
    uint32_t err = 0;
    size_t i = 0;
    unsigned char byte;
    uint8_t numBitsSet = 0;

    if (!pSockAddr || ((pSockAddr->sa_family != AF_INET) &&
        (pSockAddr->sa_family != AF_INET6)) ||
        !pPrefix)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    //14 is the size of sa_data in struct sockaddr
    for (i = 0; i < 14; i++)
    {
        byte = pSockAddr->sa_data[i];
        while (byte)
        {
            if ((byte & 0x01))
            {
                numBitsSet++;
            }
            byte = byte >> 1 ;
        }
    }

    *pPrefix = numBitsSet;

cleanup:
    return err;

error:
    goto cleanup;
}

void
free_netlink_message(
    NETLINK_MESSAGE *pNetLinkMsg
)
{
    NETLINK_MESSAGE *pCurrent = NULL;
    while (pNetLinkMsg)
    {
        pCurrent = pNetLinkMsg;
        pNetLinkMsg = pNetLinkMsg->pNext;
        netmgr_free(pCurrent->pMsg);
        netmgr_free(pCurrent);
    }
}

uint32_t
open_netlink_socket(
    uint32_t netLinkGroup,
    int *pSockFd
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct sockaddr_nl addr;

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
    fcntl(sockFd, F_SETFL, O_NONBLOCK);
    memset((void *)&addr, 0, sizeof(addr));

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = netLinkGroup;

    if (bind(sockFd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *pSockFd = sockFd;

cleanup:
    return err;
error:
    if (pSockFd)
    {
        *pSockFd = -1;
    }
    goto cleanup;
}

static uint32_t
fill_netlink_msg(
    struct nlmsghdr *nlHdr,
    PNET_NETLINK_MESSAGE *ppNetLinkMessageList
)
{
    uint32_t err = 0;
    struct ifinfomsg *pIfInfo = NULL;
    struct ifaddrmsg *pIfAddr = NULL;
    PNET_NETLINK_MESSAGE pNetLinkMsg = NULL;

    if (!nlHdr || !ppNetLinkMessageList ||
        (nlHdr->nlmsg_type == NLMSG_ERROR) || (nlHdr->nlmsg_type == NLMSG_DONE))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(NETLINK_MESSAGE), (void **)&pNetLinkMsg);
    bail_on_error(err);

    switch (nlHdr->nlmsg_type)
    {
        case RTM_NEWADDR:
            pIfAddr = NLMSG_DATA(nlHdr);
            pNetLinkMsg->netLinkMessageType = nlHdr->nlmsg_type;
            pNetLinkMsg->msgLen = IFA_PAYLOAD(nlHdr);
            err = netmgr_alloc(pNetLinkMsg->msgLen, (void **)&pNetLinkMsg->pMsg);
            bail_on_error(err);
            memcpy(pNetLinkMsg->pMsg, pIfAddr, pNetLinkMsg->msgLen);
            pNetLinkMsg->pNext = *ppNetLinkMessageList;
            *ppNetLinkMessageList = pNetLinkMsg;
            break;

        case RTM_NEWLINK:
            pIfInfo = NLMSG_DATA(nlHdr);
            pNetLinkMsg->netLinkMessageType = nlHdr->nlmsg_type;
            pNetLinkMsg->msgLen = nlHdr->nlmsg_len -
                                  NLMSG_LENGTH(sizeof(pIfInfo));
            err = netmgr_alloc(pNetLinkMsg->msgLen, (void **)&pNetLinkMsg->pMsg);
            bail_on_error(err);
            memcpy(pNetLinkMsg->pMsg, NLMSG_DATA(nlHdr), pNetLinkMsg->msgLen);
            pNetLinkMsg->pNext = *ppNetLinkMessageList;
            *ppNetLinkMessageList = pNetLinkMsg;
            break;

        default:
            goto error;
    }

cleanup:
    return err;

error:
    if (pNetLinkMsg)
    {
        netmgr_free(pNetLinkMsg->pMsg);
        netmgr_free(pNetLinkMsg);
    }
    goto cleanup;
}

uint32_t
handle_netlink_event(
    const int sockFd,
    PNET_NETLINK_MESSAGE *ppNetLinkMsgList
)
{
    uint32_t err = 0;
    int readLen = 0;
#define BUFSIZE 8192
    char buf[BUFSIZE];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    struct nlmsghdr *nlHdr;
    PNET_NETLINK_MESSAGE pNetLinkMsgList = NULL;

    if (sockFd == -1)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    while (1)
    {
        readLen = 0;
        memset(buf, 0, BUFSIZE);
        readLen = recvmsg(sockFd, &msg, 0);

        if (readLen < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                err = 0;
                break;
            }
            err = errno;
            bail_on_error(err);
        }

        nlHdr = (struct nlmsghdr *)buf;

        if ((NLMSG_OK(nlHdr, readLen) == 0) ||
            (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            err = errno;
            bail_on_error(err);
        }
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }

        for (; NLMSG_OK(nlHdr, readLen); nlHdr = NLMSG_NEXT(nlHdr, readLen))
        {
            switch (nlHdr->nlmsg_type)
            {
                case RTM_NEWADDR:
                case RTM_NEWLINK:
                    err = fill_netlink_msg(nlHdr, &pNetLinkMsgList);
                    bail_on_error(err);
                    break;

                case NLMSG_ERROR:
                    err = EINVAL;
                    bail_on_error(err);

                default:
                    break;
            }
        }
    }

    *ppNetLinkMsgList = pNetLinkMsgList;

cleanup:
    return err;
error:
    if (ppNetLinkMsgList)
    {
        *ppNetLinkMsgList = NULL;
    }
    free_netlink_message(pNetLinkMsgList);
    goto cleanup;
}

