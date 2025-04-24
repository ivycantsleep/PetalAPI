/*
22-Nov-2020 moyefi implements the following Win32 APIs

GetLogicalProcessorInformationEx
*/

#include <basedll.h>
#include <_security.h>
#include <_system.h>
#include <_memory.h>

//from Wine memory.c


/* for 'data', max_len is the array count. for 'dataex', max_len is in bytes */
static NTSTATUS create_logical_proc_info( SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX **dataex, DWORD *max_len, DWORD relation )
{
  /*  static const char core_info[] = "/sys/devices/system/cpu/cpu%u/topology/%s";
    static const char cache_info[] = "/sys/devices/system/cpu/cpu%u/cache/index%u/%s";
    static const char numa_info[] = "/sys/devices/system/node/node%u/cpumap";

    FILE *fcpu_list, *fnuma_list, *f;
    DWORD len = 0, beg, end, i, j, r, num_cpus = 0, max_cpus = 0;
    char op, name[MAX_PATH];
    ULONG_PTR all_cpus_mask = 0;

    if(sysfs_count_list_elements("/sys/devices/system/cpu/present", &max_cpus) && max_cpus > MAXIMUM_PROCESSORS)
    {
        FIXME("Improve CPU info reporting: system supports %u logical cores, but only %u supported!\n",
                max_cpus, MAXIMUM_PROCESSORS);
    }

    fcpu_list = fopen("/sys/devices/system/cpu/online", "r");
    if (!fcpu_list) return STATUS_NOT_IMPLEMENTED;

    while (!feof(fcpu_list))
    {
        if (!fscanf(fcpu_list, "%u%c ", &beg, &op)) break;
        if (op == '-') fscanf(fcpu_list, "%u%c ", &end, &op);
        else end = beg;

        for(i = beg; i <= end; i++)
        {
            DWORD phys_core = 0;
            ULONG_PTR thread_mask = 0;

            if (i > 8*sizeof(ULONG_PTR))
            {
                FIXME("skipping logical processor %d\n", i);
                continue;
            }

            if (relation == RelationAll || relation == RelationProcessorPackage)
            {
                sprintf(name, core_info, i, "physical_package_id");
                f = fopen(name, "r");
                if (f)
                {
                    fscanf(f, "%u", &r);
                    fclose(f);
                }
                else r = 0;
                if (!logical_proc_info_add_by_id(data, dataex, &len, max_len, RelationProcessorPackage, r, (ULONG_PTR)1 << i))
                {
                    fclose(fcpu_list);
                    return STATUS_NO_MEMORY;
                }
            }

            if(relation == RelationAll || relation == RelationProcessorCore ||
               relation == RelationNumaNode || relation == RelationGroup)
            {
                sprintf(name, core_info, i, "thread_siblings");
                if(!sysfs_parse_bitmap(name, &thread_mask)) thread_mask = 1<<i;

                all_cpus_mask |= thread_mask;

                if (relation == RelationAll || relation == RelationProcessorCore)
                {
                    sprintf(name, core_info, i, "thread_siblings_list");
                    f = fopen(name, "r");
                    if (f)
                    {
                        fscanf(f, "%d%c", &phys_core, &op);
                        fclose(f);
                    }
                    else phys_core = i;

                    if (!logical_proc_info_add_by_id(data, dataex, &len, max_len, RelationProcessorCore, phys_core, thread_mask))
                    {
                        fclose(fcpu_list);
                        return STATUS_NO_MEMORY;
                    }
                }
            }

            if (relation == RelationAll || relation == RelationCache)
            {
                for(j = 0; j < 4; j++)
                {
                    CACHE_DESCRIPTOR cache;
                    ULONG_PTR mask = 0;

                    sprintf(name, cache_info, i, j, "shared_cpu_map");
                    if(!sysfs_parse_bitmap(name, &mask)) continue;

                    sprintf(name, cache_info, i, j, "level");
                    f = fopen(name, "r");
                    if(!f) continue;
                    fscanf(f, "%u", &r);
                    fclose(f);
                    cache.Level = r;

                    sprintf(name, cache_info, i, j, "ways_of_associativity");
                    f = fopen(name, "r");
                    if(!f) continue;
                    fscanf(f, "%u", &r);
                    fclose(f);
                    cache.Associativity = r;

                    sprintf(name, cache_info, i, j, "coherency_line_size");
                    f = fopen(name, "r");
                    if(!f) continue;
                    fscanf(f, "%u", &r);
                    fclose(f);
                    cache.LineSize = r;

                    sprintf(name, cache_info, i, j, "size");
                    f = fopen(name, "r");
                    if(!f) continue;
                    fscanf(f, "%u%c", &r, &op);
                    fclose(f);
                    if(op != 'K')
                        WARN("unknown cache size %u%c\n", r, op);
                    cache.Size = (op=='K' ? r*1024 : r);

                    sprintf(name, cache_info, i, j, "type");
                    f = fopen(name, "r");
                    if(!f) continue;
                    fscanf(f, "%s", name);
                    fclose(f);
                    if (!memcmp(name, "Data", 5))
                        cache.Type = CacheData;
                    else if(!memcmp(name, "Instruction", 11))
                        cache.Type = CacheInstruction;
                    else
                        cache.Type = CacheUnified;

                    if (!logical_proc_info_add_cache(data, dataex, &len, max_len, mask, &cache))
                    {
                        fclose(fcpu_list);
                        return STATUS_NO_MEMORY;
                    }
                }
            }
        }
    }
    fclose(fcpu_list);

    num_cpus = count_bits(all_cpus_mask);

    if(relation == RelationAll || relation == RelationNumaNode)
    {
        fnuma_list = fopen("/sys/devices/system/node/online", "r");
        if (!fnuma_list)
        {
            if (!logical_proc_info_add_numa_node(data, dataex, &len, max_len, all_cpus_mask, 0))
                return STATUS_NO_MEMORY;
        }
        else
        {
            while (!feof(fnuma_list))
            {
                if (!fscanf(fnuma_list, "%u%c ", &beg, &op))
                    break;
                if (op == '-') fscanf(fnuma_list, "%u%c ", &end, &op);
                else end = beg;

                for (i = beg; i <= end; i++)
                {
                    ULONG_PTR mask = 0;

                    sprintf(name, numa_info, i);
                    if (!sysfs_parse_bitmap( name, &mask )) continue;

                    if (!logical_proc_info_add_numa_node(data, dataex, &len, max_len, mask, i))
                    {
                        fclose(fnuma_list);
                        return STATUS_NO_MEMORY;
                    }
                }
            }
            fclose(fnuma_list);
        }
    }

    if(dataex && (relation == RelationAll || relation == RelationGroup))
        logical_proc_info_add_group(dataex, &len, max_len, num_cpus, all_cpus_mask);

    if(data)
        *max_len = len * sizeof(**data);
    else
        *max_len = len;
*/
    return STATUS_SUCCESS;
}
