/* kernel.c -- updater patches
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2kern/ctrl.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <taihen.h>

#include <stdio.h>
#include <string.h>

#define APP_PATH "ux0:app/MODORU000/"

#define MOD_LIST_SIZE 128

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

int ksceAppMgrLaunchAppByPath(const char *name, const char *cmd, int cmdlen, int dynamic, void *opt, void *id);

static tai_hook_ref_t ksceKernelStartPreloadedModulesRef;
static tai_hook_ref_t ksceSblACMgrIsDevelopmentModeRef;
static tai_hook_ref_t SceSysrootForDriver_421EFC96_ref;
static tai_hook_ref_t SceSysrootForDriver_55392965_ref;
static tai_hook_ref_t ksceSblSmCommCallFuncRef;

#include "lv0.h"

static SceUID hooks[5];
static int newFw = 0, skipSoftMin = 0;

static int ksceKernelStartPreloadedModulesPatched(SceUID pid) {
  int res = TAI_CONTINUE(int, ksceKernelStartPreloadedModulesRef, pid);

  char titleid[32];
  ksceKernelGetProcessTitleId(pid, titleid, sizeof(titleid));

  if (strcmp(titleid, "NPXS10999") == 0) {
    ksceKernelLoadStartModuleForPid(pid, "vs0:sys/external/libshellsvc.suprx", 0, NULL, 0, NULL, NULL);
    ksceKernelLoadStartModuleForPid(pid, APP_PATH "modoru_user.suprx", 0, NULL, 0, NULL, NULL);
  }

  return res;
}

static int ksceSblACMgrIsDevelopmentModePatched(void) {
  TAI_CONTINUE(int, ksceSblACMgrIsDevelopmentModeRef);
  return 1;
}

static int SceSysrootForDriver_421EFC96_patched(void) {
  TAI_CONTINUE(int, SceSysrootForDriver_421EFC96_ref);
  return 0;
}

static int SceSysrootForDriver_55392965_patched(void) {
  TAI_CONTINUE(int, SceSysrootForDriver_55392965_ref);
  return 1;
}

static int ksceSblSmCommCallFuncPatched(int id, int service_id, int *f00d_resp, void *data, int size) {
	
  if (newFw) { // current > 3.71
    if (service_id == SCE_SBL_SM_COMM_FID_SM_SNVS_ENCDEC_SECTORS && *(uint32_t*)data == 2) // enc/dec snvs, mode 2
      lv0_nop32(0x0080bb8c, id); // remove fw check error
    else if (skipSoftMin && service_id == SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG) { // target < 1.692
      lv0_nop32(0x0080fea0, id); // remove 1.692 soft min fw checks
      lv0_nop32(0x00810370, id);
    }
  } else if (!newFw && skipSoftMin && service_id == SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG) { // current < 3.72, target < 1.692
    lv0_nop32(0x0080fe44, id); // remove 1.692 soft min fw checks
    lv0_nop32(0x0080fe48, id);
    lv0_nop32(0x00810298, id);
    lv0_nop32(0x0081029C, id);
  }
	
  int res = TAI_CONTINUE(int, ksceSblSmCommCallFuncRef, id, service_id, f00d_resp, data, size);

  if (f00d_resp && service_id == SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG && *f00d_resp == 0x800F0237) // fw cmp error
    *f00d_resp = 0; // The spkg has actually been decrypted successfully, just fake success

  return res;
}

int k_modoru_release_updater_patches(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  if (hooks[4] >= 0)
    taiHookReleaseForKernel(hooks[4], ksceSblSmCommCallFuncRef);
  if (hooks[3] >= 0)
    taiHookReleaseForKernel(hooks[3], SceSysrootForDriver_55392965_ref);
  if (hooks[2] >= 0)
    taiHookReleaseForKernel(hooks[2], SceSysrootForDriver_421EFC96_ref);
  if (hooks[1] >= 0)
    taiHookReleaseForKernel(hooks[1], ksceSblACMgrIsDevelopmentModeRef);
  if (hooks[0] >= 0)
    taiHookReleaseForKernel(hooks[0], ksceKernelStartPreloadedModulesRef);

  EXIT_SYSCALL(state);
  return 0;
}

int k_modoru_patch_updater(int setSkipSoftMin, int setNewFw) {
  int res;
  uint32_t state;
  ENTER_SYSCALL(state);

  newFw = setNewFw;
  skipSoftMin = setSkipSoftMin;
  
  memset(hooks, -1, sizeof(hooks));

  res = hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelStartPreloadedModulesRef, "SceKernelModulemgr",
                                                  TAI_ANY_LIBRARY, 0x432DCC7A, ksceKernelStartPreloadedModulesPatched);
  if (res < 0) {
    res = hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelStartPreloadedModulesRef, "SceKernelModulemgr",
                                                    TAI_ANY_LIBRARY, 0x998C7AE9, ksceKernelStartPreloadedModulesPatched);
  }

  if (res < 0)
    goto err;

  res = hooks[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceAppMgr",
                                                  TAI_ANY_LIBRARY, 0xBBA13D9C, ksceSblACMgrIsDevelopmentModePatched);
  if (res < 0) {
    res = hooks[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceAppMgr",
                                                    TAI_ANY_LIBRARY, 0xE87D1777, ksceSblACMgrIsDevelopmentModePatched);
  }

  if (res < 0)
    goto err;

  res = hooks[2] = taiHookFunctionImportForKernel(KERNEL_PID, &SceSysrootForDriver_421EFC96_ref, "SceAppMgr",
                                                  TAI_ANY_LIBRARY, 0x421EFC96, SceSysrootForDriver_421EFC96_patched);
  if (res < 0)
    goto err;

  res = hooks[3] = taiHookFunctionImportForKernel(KERNEL_PID, &SceSysrootForDriver_55392965_ref, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0x55392965, SceSysrootForDriver_55392965_patched);
  if (res < 0)
    goto err;

  res = hooks[4] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblSmCommCallFuncRef, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0xDB9FC204, ksceSblSmCommCallFuncPatched);
  if (res < 0)
    goto err;

  EXIT_SYSCALL(state);
  return 0;

err:
  k_modoru_release_updater_patches();
  EXIT_SYSCALL(state);
  return res;
}

static int launch_thread(SceSize args, void *argp) {
  int opt[52/4];
  memset(opt, 0, sizeof(opt));
  opt[0] = sizeof(opt);

  ksceAppMgrLaunchAppByPath("ud0:PSP2UPDATE/psp2swu.self", NULL, 0, 0, opt, NULL);

  return ksceKernelExitDeleteThread(0);
}

int k_modoru_launch_updater(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  SceUID thid = ksceKernelCreateThread("launch_thread", (SceKernelThreadEntry)launch_thread, 0x40, 0x1000, 0, 0, NULL);
  if (thid < 0) {
    EXIT_SYSCALL(state);
    return thid;
  }

  ksceKernelStartThread(thid, 0, NULL);

  EXIT_SYSCALL(state);
  return 0;
}

int k_modoru_detect_plugins(void) {
  SceKernelModuleInfo info;
  SceUID modlist[MOD_LIST_SIZE];
  size_t count = MOD_LIST_SIZE;
  int res;

  uint32_t state;
  ENTER_SYSCALL(state);

  int (* _ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
  int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

  res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                               0x97CF7B4E, (uintptr_t *)&_ksceKernelGetModuleList);
  if (res < 0)
    res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                                 0xB72C75A4, (uintptr_t *)&_ksceKernelGetModuleList);
  if (res < 0)
    goto err;

  res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                               0xD269F915, (uintptr_t *)&_ksceKernelGetModuleInfo);
  if (res < 0)
    res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                                 0xDAA90093, (uintptr_t *)&_ksceKernelGetModuleInfo);
  if (res < 0)
    goto err;

  res = _ksceKernelGetModuleList(KERNEL_PID, 0x7fffffff, 1, modlist, &count);
  if (res < 0)
    goto err;

  info.size = sizeof(SceKernelModuleInfo);
  res = _ksceKernelGetModuleInfo(KERNEL_PID, modlist[2], &info);
  if (res < 0)
    goto err;

  // Third last kernel module must be either taihen or HENkaku
  if (strcmp(info.module_name, "taihen") != 0 && strcmp(info.module_name, "HENkaku") != 0) {
    res = 1;
    goto err;
  }

  res = _ksceKernelGetModuleList(ksceKernelGetProcessId(), 0x7fffffff, 1, modlist, &count);
  if (res < 0)
    goto err;

  info.size = sizeof(SceKernelModuleInfo);
  res = _ksceKernelGetModuleInfo(ksceKernelGetProcessId(), modlist[1], &info);
  if (res < 0)
    goto err;

  // Second last user module must be SceAppUtil
  if (strcmp(info.module_name, "SceAppUtil") != 0) {
    res = 1;
    goto err;
  }

  res = 0;

err:
  EXIT_SYSCALL(state);
  return res;
}

int k_modoru_get_factory_firmware(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  unsigned int factory_fw = -1;

  void *sysroot = ksceKernelGetSysrootBuffer();
  if (sysroot)
    factory_fw = *(unsigned int *)(sysroot + 8);

  EXIT_SYSCALL(state);
  return factory_fw;
}

int k_modoru_ctrl_peek_buffer_positive(int port, SceCtrlData *pad_data, int count) {
  SceCtrlData pad;
  uint32_t off;

  uint32_t state;
  ENTER_SYSCALL(state);

  // Set cpu offset to zero
  asm volatile ("mrc p15, 0, %0, c13, c0, 4" : "=r" (off));
  asm volatile ("mcr p15, 0, %0, c13, c0, 4" :: "r" (0));

  int res = ksceCtrlPeekBufferPositive(port, &pad, count);

  // Restore cpu offset
  asm volatile ("mcr p15, 0, %0, c13, c0, 4" :: "r" (off));

  ksceKernelMemcpyKernelToUser((uintptr_t)pad_data, &pad, sizeof(SceCtrlData));

  EXIT_SYSCALL(state);
  return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp) {
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  k_modoru_release_updater_patches();
  return SCE_KERNEL_STOP_SUCCESS;
}
