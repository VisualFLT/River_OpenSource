#ifndef __RIVER_LICENSE_ACTIVATION_H__
#define __RIVER_LICENSE_ACTIVATION_H__

#include <windows.h>

_Success_(return)
BOOL Activation_Initialize();

_Success_(return)
BOOL Activation_IsAuthorized();

VOID Activation_Shutdown();

#endif /* __RIVER_LICENSE_ACTIVATION_H__ */
