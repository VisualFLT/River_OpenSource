#pragma once

#ifndef LEECH_AGENT_LOG_ENABLED
#define LEECH_AGENT_LOG_ENABLED 0
#endif

#if !LEECH_AGENT_LOG_ENABLED
#define printf(...) ((void)0)
#endif

