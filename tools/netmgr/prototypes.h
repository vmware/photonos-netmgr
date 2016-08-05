/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
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

void
show_version(
    );

uint32_t
cmd_help(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_ifup(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_ifdown(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_list(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_set_iaid(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_get_iaid(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_set_duid(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_get_duid(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_set_dns_servers(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_get_dns_servers(
    PNETMGR_CMD_ARGS pCmdArgs
    );

uint32_t
cmd_set_dns_servers_v0(
    PNETMGR_CMD_ARGS pCmdArgs
    );

//uint32_t
//cmd_dns_servers(
//    PNETMGR_CMD_ARGS pCmdArgs
//    );

//parse_args.c
uint32_t
parse_args(
    int argc,
    char** argv,
    PNETMGR_CMD_ARGS* ppCmdArgs
    );

uint32_t
copy_cmd_args(
    PNETMGR_CMD_ARGS pOptions,
    PNETMGR_CMD_ARGS pCmdArgs
    );

void
free_cmd_args(
    PNETMGR_CMD_ARGS pCmdArgs
    );
