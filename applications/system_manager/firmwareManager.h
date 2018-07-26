/*
 * firmwareManager.h
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_
#define APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_

#include "string"

namespace app
{
    class firmwareManager
    {
    private:
        typedef struct fdt_header
        {
            uint32_t magic; /* magic word FDT_MAGIC */
            uint32_t totalsize; /* total size of DT block */
            uint32_t off_dt_struct; /* offset to structure */
            uint32_t off_dt_strings; /* offset to strings */
            uint32_t off_mem_rsvmap; /* offset to memory reserve map */
            uint32_t version; /* format version */
            uint32_t last_comp_version; /* last compatible version */

            /* version 2 fields below */
            uint32_t boot_cpuid_phys; /* Which physical CPU id we're booting on */

            /* version 3 fields below */
            uint32_t size_dt_strings; /* size of the strings block */

            /* version 17 fields below */
            uint32_t size_dt_struct; /* size of the structure block */
        } firmware_header;

        firmwareManager();
        static firmwareManager* s_instance;
        std::string firmware_name;

        bool firmwareValidator(const char *filename);

    public:
        virtual ~firmwareManager();

        static firmwareManager* getInstance();
        std::string getFirmwareName();

        void setFirmwareName(std::string &filename);

        uint16_t doFirmwareUpgrade();
    };

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_ */
