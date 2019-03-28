#ifndef __COMMON_DYNFUNCS_H_
#define __COMMON_DYNFUNCS_H_

uint8_t* dynfuncs_get_module_base_by_hash(uint32_t dwHash);
puint_t dynfuncs_get_symbol_by_hash(uint8_t* moduleBase, uint32_t dwHash);
int dynfuncs_load(int bOnlyBaseDlls);

#endif // __COMMON_DYNFUNCS_H_
