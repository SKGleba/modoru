/* main.c -- launcher
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2/appmgr.h>
#include <psp2/ctrl.h>
#include <psp2/power.h>
#include <psp2/shellutil.h>
#include <psp2/vshbridge.h>
#include <psp2/io/devctl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/io/dirent.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>

#include "pspdebug.h"

#define printf psvDebugScreenPrintf

#define CHUNK_SIZE 64 * 1024

#define WHITE  0x00FFFFFF
#define YELLOW 0x0000FFFF

int k_modoru_release_updater_patches(void);
int k_modoru_patch_updater(void);
int k_modoru_launch_updater(void);
int k_modoru_detect_plugins(void);
int k_modoru_get_factory_firmware(void);
int k_modoru_ctrl_peek_buffer_positive(int port, SceCtrlData* pad_data, int count);
int k_modoru_add_enso(void* u_eobuf);

void ErrorExit(int milisecs, char *fmt, ...) {
  va_list list;
  char msg[256];

  va_start(list, fmt);
  vsprintf(msg, fmt, list);
  va_end(list);

  printf(msg);

  sceKernelDelayThread(milisecs * 1000);

  sceKernelPowerUnlock(0);
  sceKernelExitProcess(0);
}

void firmware_string(char string[8], unsigned int version) {
  char a = (version >> 24) & 0xf;
  char b = (version >> 20) & 0xf;
  char c = (version >> 16) & 0xf;
  char d = (version >> 12) & 0xf;

  memset(string, 0, 8);
  string[0] = '0' + a;
  string[1] = '.';
  string[2] = '0' + b;
  string[3] = '0' + c;
  string[4] = '\0';

  if (d) {
    string[4] = '0' + d;
    string[5] = '\0';
  }
}

void wait_confirm(const char *msg) {
  printf(msg);

  while (1) {
    SceCtrlData pad;
    sceCtrlPeekBufferPositive(0, &pad, 1);

    if (pad.buttons & SCE_CTRL_CROSS) {
      break;
    } else if (pad.buttons & (SCE_CTRL_RTRIGGER | SCE_CTRL_R1)) {
      ErrorExit(5000, "Exiting in 5 seconds.\n");
    }

    sceKernelDelayThread(10000);
  }

  sceKernelDelayThread(500 * 1000);
}

int addEnso(void) {
  SceUID fd = sceIoOpen("ud0:enso.eo", SCE_O_RDONLY, 0);
  if (fd < 0)
    return 0;
  char* tmp_ensonx_blk = malloc(0x2E * 0x200);
  sceIoRead(fd, tmp_ensonx_blk, 0x2E * 0x200);
  sceIoClose(fd);
  if (k_modoru_add_enso(tmp_ensonx_blk) < 0)
    return 0;
  return 1;
}

int main(int argc, char *argv[]) {
  int res;
  int bypass = 0, installEnso = 0;

  psvDebugScreenInit();
  sceKernelPowerLock(0);

  printf("-- modoru v2.1 (tiny)\n");
  printf("   by TheFloW, mod by SKGleba\n\n");

  SceKernelFwInfo fwinfo;
  fwinfo.size = sizeof(SceKernelFwInfo);
  _vshSblGetSystemSwVersion(&fwinfo);

  unsigned int current_version = (unsigned int)fwinfo.version;
  unsigned int factory_version = k_modoru_get_factory_firmware();

  char current_fw[8], factory_fw[8];
  firmware_string(current_fw, current_version);
  firmware_string(factory_fw, factory_version);

  printf("Firmware information:\n");
  printf(" - Current firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", current_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n");
  printf(" - Factory firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", factory_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n\n");

  SceCtrlData pad;
  k_modoru_ctrl_peek_buffer_positive(0, &pad, 1);
  if (pad.buttons & (SCE_CTRL_LTRIGGER | SCE_CTRL_R1)) {
    bypass = 1;
  }

  if (!bypass) {
    if (scePowerGetBatteryLifePercent() < 7)
      ErrorExit(10000, "Battery has to be at least at 7 percents.\n");
  }

  char header[0x80];

  SceUID fd = sceIoOpen("ud0:PSP2UPDATE/PSP2UPDAT.PUP", SCE_O_RDONLY, 0);
  if (fd < 0)
    ErrorExit(10000, "Error 0x%08X opening %s.\n", fd, "ud0:PSP2UPDATE/PSP2UPDAT.PUP");
  sceIoRead(fd, header, sizeof(header));
  sceIoClose(fd);

  if (strncmp(header, "SCEUF", 5) != 0)
    ErrorExit(10000, "Error invalid updater file.\n");

  unsigned int target_version  = *(unsigned int *)(header + 0x10);

  char target_fw[8];
  firmware_string(target_fw,  target_version);
  
  installEnso = addEnso();

  printf("Target firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", target_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n");
  printf(" - install enso: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", (installEnso) ? "yes" : "no");
  psvDebugScreenSetTextColor(WHITE);
  printf("\n\n");

  if (target_version < factory_version)
    ErrorExit(10000, "Error you cannot go lower than your factory firmware.");

  if (!bypass) {
	if (current_version > 0x03730011)
		ErrorExit(10000, "Error your current system software version is not supported.");
  }

  if (target_version == current_version) {
    printf("Do you want to reinstall firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  } else if (target_version < current_version) {
    printf("Do you want to downgrade from firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf(" to firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", target_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  } else if (target_version > current_version) {
    printf("Do you want to update from firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf(" to firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", target_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  }

  wait_confirm("Press X to confirm, R to exit.\n\n");

  printf("This software will make PERMANENT modifications to your Vita.\n"
         "If anything goes wrong, there is NO RECOVERY (not even with a\n"
         "hardware flasher). The creators provide this tool \"as is\", without\n"
         "warranty of any kind, express or implied and cannot be held liable\n"
         "for any damage done.\n\n");

  if (!bypass) {
    printf("Continues in 20 seconds.\n\n");
    sceKernelDelayThread(20 * 1000 * 1000);
  }

  wait_confirm("Press X to accept these terms and start the installation,\n"
               "      R to not accept and exit.\n\n");

  printf("Removing ux0:id.dat...");
  res = sceIoRemove("ux0:id.dat");
  if (res < 0)
    printf("Error 0x%08X deleting ux0:id.dat.\n", res);
  else
    printf("OK\n");
  sceKernelDelayThread(500 * 1000);

  printf("Starting SCE updater...\n");
  sceKernelDelayThread(1 * 1000 * 1000);

  sceKernelPowerUnlock(0);

  res = k_modoru_patch_updater();
  if (res < 0)
    ErrorExit(10000, "Error 0x%08X patching updater.\n", res);

  res = k_modoru_launch_updater();
  if (res < 0)
    goto err;

  sceKernelDelayThread(10 * 1000 * 1000);

err:
  k_modoru_release_updater_patches();
  ErrorExit(10000, "Error 0x%08X starting SCE updater.\n", res);

  return 0;
}
