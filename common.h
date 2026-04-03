#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef CCCAM_SRV
#define CCCAM
#else
#ifdef CCCAM_CLI
#define CCCAM
#endif
#endif

#ifdef RADEGAST_SRV
#define RADEGAST
#else
#ifdef RADEGAST_CLI
#define RADEGAST
#endif
#endif

#define REVISION    82
#define REVISION_STR  "82"

#define FALSE 0
#define TRUE 1

#ifdef WIN32

#define pthread_t DWORD

#else

typedef int SOCKET;
#define INVALID_HANDLE_VALUE -1
#define INVALID_SOCKET       -1
#define SOCKET_ERROR         -1
#define closesocket          close

#endif

#define MAX_ECM_SIZE 700

struct message_data
{
int len;
unsigned char data[2048]; // max size for cccam servers/clients
};

#define MAX_PFD 1024*15
#define SERVER_MAX_PFD 1024*2
#define CCCAM_MAX_PFD 1024*10
#define MGCAMD_MAX_PFD 1024*10
#define NEWCAMD_MAX_PFD 512
#define CACHEEX_MAX_PFD 1024

#define LOGCRITICAL 0
#define LOGERROR 1
#define LOGWARNING 2
#define LOGINFO 3
#define LOGDEBUG 4
#define LOGTRACE 5

///////////////////////////////////////////////////////////////////////////////
// CAID family constants (Phase 1 — provider-aware routing)
///////////////////////////////////////////////////////////////////////////////
#define CAID_MASK_FAMILY    0xff00  /* high byte mask for CAID family   */
#define CAID_SECA           0x0100  /* Seca Mediaguard (provider-aware) */
#define CAID_VIACCESS       0x0500  /* Viaccess        (provider-aware) */
#define CAID_IRDETO         0x0600  /* Irdeto                           */
#define CAID_VIDEOGUARD     0x0900  /* NDS VideoGuard                   */
#define CAID_CONAX          0x0b00  /* Conax                            */
#define CAID_CRYPTOWORKS    0x0d00  /* CryptoWorks                      */
#define CAID_BETACRYPT      0x1700  /* BetaCrypt                        */
#define CAID_NAGRA          0x1800  /* Nagra                            */
#define CAID_BULCRYPT1      0x5581  /* Bulcrypt (provider 000001)       */
#define CAID_BULCRYPT2      0x4AEE  /* Bulcrypt alternative CAID        */
#define CAID_DRE_CRYPT      0x4AE0  /* DRE-Crypt                        */

/* When CAID_BULCRYPT_PROV is defined, Bulcrypt ECMs are matched by both
   CAID and provider (mirrors Seca/Viaccess behaviour in match_card()).
   Enable at compile time: make ... EXTRA_OPTS="-DCAID_BULCRYPT_PROV"    */

#endif