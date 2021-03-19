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

#define ENSONX_CRC_OLD 0xDD3C459B
#define ENSONX_CRC_NEW 0x52CBF098
#define SL_CRC_OLD 0x3D2B73D7
#define SL_CRC_NEW 0xDB02B893
#define SCE_SBL_ERROR_SL_EDATA   0x800F0226
#define SCE_SBL_ERROR_SL_ESYSVER 0x800F0237
#define SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG 0x40002
#define ARRAYSIZE(x) ((sizeof(x) / sizeof(0 [x])) / ((size_t)(!(sizeof(x) % sizeof(0 [x])))))

#define NZERO_RANGE(off, end, ctx) \
	do { \
		int curr = 0; \
		while (off + curr < end + 4) { \
			nzero32((off + curr), ctx); \
			curr = curr + 4; \
		} \
} while (0)

typedef struct {
  uint32_t off;
  uint32_t sz;
  uint8_t code;
  uint8_t type;
  uint8_t active;
  uint32_t flags;
  uint16_t unk;
} __attribute__((packed)) partition_t;

typedef struct {
  char magic[0x20];
  uint32_t version;
  uint32_t device_size;
  char unk1[0x28];
  partition_t partitions[0x10];
  char unk2[0x5e];
  char unk3[0x10 * 4];
  uint16_t sig;
} __attribute__((packed)) master_block_t;

typedef struct {
  void *addr;
  uint32_t length;
} __attribute__((packed)) region_t;

typedef struct {
  uint32_t unused_0[2];
  uint32_t use_lv2_mode_0; // if 1, use lv2 list
  uint32_t use_lv2_mode_1; // if 1, use lv2 list
  uint32_t unused_10[3];
  uint32_t list_count; // must be < 0x1F1
  uint32_t unused_20[4];
  uint32_t total_count; // only used in LV1 mode
  uint32_t unused_34[1];
  union {
    region_t lv1[0x1F1];
    region_t lv2[0x1F1];
  } list;
} __attribute__((packed)) cmd_0x50002_t;

typedef struct heap_hdr {
  void *data;
  uint32_t size;
  uint32_t size_aligned;
  uint32_t padding;
  struct heap_hdr *prev;
  struct heap_hdr *next;
} __attribute__((packed)) heap_hdr_t;

#include "crc32.c"

cmd_0x50002_t cargs;

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

int ksceAppMgrLaunchAppByPath(const char *name, const char *cmd, int cmdlen, int dynamic, void *opt, void *id);

static tai_hook_ref_t ksceKernelStartPreloadedModulesRef;
static tai_hook_ref_t ksceSblACMgrIsDevelopmentModeRef;
static tai_hook_ref_t SceSysrootForDriver_421EFC96_ref;
static tai_hook_ref_t SceSysrootForDriver_55392965_ref;
static tai_hook_ref_t ksceSblSmCommCallFuncRef;
static tai_hook_ref_t sceSblSsUpdateMgrSendCommandRef;

static SceUID hooks[5];
void* eobuf = NULL;
static int doInject = 0, resetHooked = 0, emmc = 0;
static int (*read_real_mmc)(int target, uint32_t off, void* dst, uint32_t sz) = NULL;

static int ksceKernelStartPreloadedModulesPatched(SceUID pid) {
  int res = TAI_CONTINUE(int, ksceKernelStartPreloadedModulesRef, pid);

  char titleid[32];
  ksceKernelSysrootGetProcessTitleId(pid, titleid, sizeof(titleid));

  if (strcmp(titleid, "NPXS10999") == 0) {
    ksceKernelLoadStartModuleForPid(pid, "vs0:sys/external/libshellsvc.suprx", 0, NULL, 0, NULL, NULL);
    ksceKernelLoadStartModuleForPid(pid, "ud0:tiny_modoru_user.suprx", 0, NULL, 0, NULL, NULL);
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

static int nzero32(uint32_t addr, int ctx) {
  int ret = 0, sm_ret = 0;
  memset(&cargs, 0, sizeof(cargs));
  cargs.use_lv2_mode_0 = cargs.use_lv2_mode_1 = 0;
  cargs.list_count = 3;
  cargs.total_count = 1;
  cargs.list.lv1[0].addr = cargs.list.lv1[1].addr = 0x50000000;
  cargs.list.lv1[0].length = cargs.list.lv1[1].length = 0x10;
  cargs.list.lv1[2].addr = 0;
  cargs.list.lv1[2].length = addr - offsetof(heap_hdr_t, next);
  ret = TAI_CONTINUE(int, ksceSblSmCommCallFuncRef, ctx, 0x50002, &sm_ret, &cargs, sizeof(cargs));
  if (sm_ret < 0) {
    return sm_ret;
  }
  return ret;
}

static int ksceSblSmCommCallFuncPatched(int id, int service_id, int *f00d_resp, void *data, int size) {
	
  if (doInject == 1 && service_id == 0xb0002)
	   NZERO_RANGE(0x0080bb44, 0x0080bb98, id);
	
  int res = TAI_CONTINUE(int, ksceSblSmCommCallFuncRef, id, service_id, f00d_resp, data, size);

  if (f00d_resp && service_id == SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG && *f00d_resp == SCE_SBL_ERROR_SL_ESYSVER)
    *f00d_resp = 0;

  return res;
}

// find partition [part_id] with active flag set to [active] in sce mbr [master]
int find_part(master_block_t* master, uint8_t part_id, uint8_t active) {
  for (size_t i = 0; i < ARRAYSIZE(master->partitions); ++i) {
    if (master->partitions[i].code == part_id && master->partitions[i].active == active)
      return i;
  }
  return -1;
}

int sceSblSsUpdateMgrSendCommandPatched(int cmd, int arg) {
  if ((uint32_t)cmd > 1 || emmc == 0 || read_real_mmc == NULL)
    return TAI_CONTINUE(int, sceSblSsUpdateMgrSendCommandRef, cmd, arg);
  
  uint32_t state = 0;
  ENTER_SYSCALL(state);
  
  ksceDebugPrintf("send command coldreset/standby\n");
  
  // alloc a 2MB memblock in camera SRAM
  ksceDebugPrintf("alloc memblock...\n");
  SceKernelAllocMemBlockKernelOpt optp;
  optp.size = 0x58;
  optp.attr = 2;
  optp.paddr = 0x1c000000;
  void* eobuf = NULL;
  ksceKernelGetMemBlockBase(ksceKernelAllocMemBlock("sram_cam", 0x60208006, 0x200000, &optp), (void**)&eobuf);
  if (eobuf == NULL)
    goto err;
  
  // get expected second_loader crc32
  ksceDebugPrintf("get exp crc...\n");
  uint32_t exp_crc = 0;
  uint32_t eobuf_crc = crc32(0, eobuf, 0x2E * 0x200);
  if (eobuf_crc == ENSONX_CRC_OLD)
    exp_crc = SL_CRC_OLD;
  else if (eobuf_crc == ENSONX_CRC_NEW)
    exp_crc = SL_CRC_NEW;
  ksceDebugPrintf("enso 0x%X => SL 0x%X\n", eobuf_crc, exp_crc);
  if (exp_crc == 0)
    goto err;
  
  // read the current real MBR
  ksceDebugPrintf("reading the MBR...\n");
  char block[0x200];
  master_block_t* mbr = (master_block_t * )block;
  if (read_real_mmc(emmc, 0, mbr, 1) < 0)
    goto err;
  
  // check if second_loader block 0 (fw string) crc32 matches the expected one
  // TODO: crc arm kbl instead to future-proof from the CLever exploit
  ksceDebugPrintf("read SL str...");
  char slstr[0x200];
  int pno_slsk = find_part(mbr, 2, 1);
  if (pno_slsk < 0 || read_real_mmc(emmc, 1 + mbr->partitions[pno_slsk].off, slstr, 1) < 0)
    goto err;
  ksceDebugPrintf("cmp SL str crc...\n");
  if (crc32(0, slstr + 0x40, 0x10) != exp_crc)
    goto err;
  
  // writeback the MBR to block 0 and block 1
  ksceDebugPrintf("cleaning the BR...\n");
  if (ksceSdifWriteSectorMmc(emmc, 0, mbr, 1) < 0 || ksceSdifWriteSectorMmc(emmc, 1, mbr, 1) < 0)
    goto err;
  
  // write enso to sector 2+
  ksceDebugPrintf("writing enso...\n");
  if (ksceSdifWriteSectorMmc(emmc, 2, eobuf, 0x2E) < 0)
    goto err;
  
  // update the MBR with enso exploit offset
  ksceDebugPrintf("installing enso...\n");
  int pno_os = find_part(mbr, 3, 1);
  if (pno_os < 0)
    goto err;
  mbr->partitions[pno_os].off = 2;
  if (ksceSdifWriteSectorMmc(emmc, 0, mbr, 1) < 0)
    goto err;
  
  ksceDebugPrintf("all done\n");
  

err:
  EXIT_SYSCALL(state);
  return TAI_CONTINUE(int, sceSblSsUpdateMgrSendCommandRef, cmd, arg);
}

int k_modoru_release_updater_patches(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  if (resetHooked > 0)
    taiHookReleaseForKernel(resetHooked, sceSblSsUpdateMgrSendCommandRef);
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

int k_modoru_patch_updater(void) {
  int res;
  uint32_t state;
  ENTER_SYSCALL(state);

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

int k_modoru_get_factory_firmware(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  unsigned int factory_fw = -1;

  void* sysroot = ksceKernelSysrootGetKblParam();
  if (sysroot) {
    factory_fw = *(unsigned int *)(sysroot + 8);
	if (*(unsigned int *)(sysroot + 4) > 0x03700011)
		doInject = 1;
  }

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

int k_modoru_add_enso(void *u_eobuf) {
  if (emmc == 0 || read_real_mmc == NULL)
    return -1;
  uint32_t state;
  ENTER_SYSCALL(state);
  SceKernelAllocMemBlockKernelOpt optp;
  optp.size = 0x58;
  optp.attr = 2;
  optp.paddr = 0x1c000000;
  int add_eo_blk = ksceKernelAllocMemBlock("add_enso_block", 0x60208006, 0x200000, &optp);
  if (add_eo_blk < 0)
    goto aerr;
  void* add_eo_base = NULL;
  ksceKernelGetMemBlockBase(add_eo_blk, (void**)&add_eo_base);
  memset(add_eo_base, 0, 0x30 * 0x200);
  ksceKernelMemcpyUserToKernel(add_eo_base, (uintptr_t)u_eobuf, 0x2E * 0x200);
  uint32_t add_eo_crc = crc32(0, add_eo_base, 0x2E * 0x200);
  ksceKernelFreeMemBlock(add_eo_blk);
  ksceDebugPrintf("add_eo_crc: 0x%X\n", add_eo_crc);
  if (add_eo_crc != ENSONX_CRC_OLD && add_eo_crc != ENSONX_CRC_NEW)
    goto aerr;
  resetHooked = taiHookFunctionExportForKernel(KERNEL_PID, &sceSblSsUpdateMgrSendCommandRef, "SceSblUpdateMgr", 0x31406C49, 0x1825D954, sceSblSsUpdateMgrSendCommandPatched);
  if (resetHooked < 0)
    goto aerr;
  EXIT_SYSCALL(state);
  return 0;
aerr:
  EXIT_SYSCALL(state);
  return -1;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp) {
  emmc = ksceSdifGetSdContextPartValidateMmc(0);
  module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSdif"), 0, 0x3e7d, (uintptr_t*)&read_real_mmc);
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  k_modoru_release_updater_patches();
  return SCE_KERNEL_STOP_SUCCESS;
}
