#include <common.h>
#include <command.h>
#include <fs.h>
#include <fat.h>
#include <asm/byteorder.h>
#include <linux/compiler.h>

static int firmware(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
    __u8 number __aligned(ARCH_DMA_MINALIGN);
    char * argv_firmware_selected[5];
    argv_firmware_selected[1] = "mmc";
    argv_firmware_selected[2] = "0:0";
    argv_firmware_selected[4] = "firmware_selected";

    char number_addr_str[32];
    snprintf(number_addr_str, 32, "%p" , &number);
    argv_firmware_selected[3] = number_addr_str;
    do_load(cmdtp, flag, 5, argv_firmware_selected, FS_TYPE_FAT);

    char * argv_firmware[5];
    argv_firmware[1] = "mmc";
    argv_firmware[2] = "0:0";
    snprintf(number_addr_str, 32, "%p" , &number);
    argv_firmware[3] = "60008000";

    if (number == '1') {
        argv_firmware[4] = "firmware_1";
    } else if (number == '0') {
        argv_firmware[4] = "firmware_0";
    }

    do_load(cmdtp, flag, 5, argv_firmware, FS_TYPE_FAT);

    char * argv_bootm[2];
    argv_bootm[1] = argv_firmware[3];
    do_bootm(cmdtp, flag, 2, argv_bootm);

    return 1;
}

U_BOOT_CMD_COMPLETE(load_firmware, 5, 1, firmware, "load firmware from firmware_selected", "arg1: start address", 0);
