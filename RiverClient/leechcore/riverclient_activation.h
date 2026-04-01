#ifndef __RIVERCLIENT_ACTIVATION_H__
#define __RIVERCLIENT_ACTIVATION_H__

#include "leechcore.h"
#include "leechcore_internal.h"

#ifdef _WIN32
_Success_(return)
BOOL RcActivation_EnsureActivated(_Inout_ PLC_CONTEXT ctxLC);
#endif /* _WIN32 */

#endif /* __RIVERCLIENT_ACTIVATION_H__ */
