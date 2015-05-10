/*
 * "Block +OK" Blocks messages that does not start with +OK!!
 * +X = No messages that are not encrypted will go any further than to the server
 * +x = 'Unencrypted text: ' will be prepended to the message if it its unencrypted
 */

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "proto.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

#define BLOCKOK_VERSION "v0.1"
#define BLOCK_OK_FLAG 'X'

#define DelCmode(x)     if (x) CmodeDel(x); x = NULL

ModuleHeader MOD_HEADER(m_block_ok)
  = {
        "m_block_ok.c", /* Name of module */
        BLOCKOK_VERSION, /* Version */
        "BlocksUnEncMsg", /* Short description of module */
        "3.2-b8-1",
        NULL
    };

static ModuleInfo NoCodesModInfo;

static Hook *CheckMsg;
static int ModeBlock_is_ok(aClient *, aChannel *, char *, int, int);
Cmode_t EXTCMODE_BLOCK = 0L;
Cmode_t EXTCMODE_BLOCK_APPEND = 0L;

Cmode *ModeBlock = NULL;
Cmode *ModeBlockAppend = NULL;
DLLFUNC char *nocodes_checkmsg(aClient *, aClient *, aChannel *, char *, int);

DLLFUNC int MOD_INIT(m_nocodes)(ModuleInfo *modinfo)
{
    CmodeInfo req;
    CmodeInfo req_append;
    memset(&req, 0, sizeof(req));
    req.paracount = 0;
    req.is_ok = ModeBlock_is_ok;
    req.flag = 'X';

    memset(&req_append, 0, sizeof(req_append));
    req_append.paracount = 0;
    req_append.is_ok = ModeBlock_is_ok;
    req_append.flag = 'x';

    ModeBlock = CmodeAdd(modinfo->handle, req, &EXTCMODE_BLOCK);
    ModeBlockAppend = CmodeAdd(modinfo->handle, req_append, &EXTCMODE_BLOCK_APPEND);
    bcopy(modinfo,&NoCodesModInfo,modinfo->size);
    CheckMsg = HookAddPCharEx(NoCodesModInfo.handle, HOOKTYPE_CHANMSG, nocodes_checkmsg);
    return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_dummy)(int module_load)
{
        return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_dummy)(int module_unload)
{
        DelCmode(ModeBlock);

        HookDel(CheckMsg);
        return MOD_SUCCESS;
}

static int ModeBlock_is_ok(aClient *sptr, aChannel *chptr, char *para, int type, int what) {
    return EX_ALLOW;
}


DLLFUNC char *nocodes_checkmsg(aClient *cptr, aClient *sptr, aChannel *chptr, char *text, int notice)
{
char retbuf[4096];

        if (chptr->mode.extmode & EXTCMODE_BLOCK_APPEND)
        {
                if (strstr(text, "+OK ") == NULL || strstr(text, "+OK ") - text != 0)
                {
                        snprintf(retbuf, 4096, "Unencrypted text: %s", text);
                        return retbuf;
                } else
                        return text;
        }
         else if (chptr->mode.extmode & EXTCMODE_BLOCK)
        {
                if (strstr(text, "+OK ") == NULL || strstr(text, "+OK ") - text != 0)
                {
                        sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN),
                                me.name, sptr->name, sptr->name,
                                "Unencrypted messages are not permitted in this channel",
                                chptr->chname);
                        return NULL;
                } else
                        return text;

        }
        else
        { return text; }
}
