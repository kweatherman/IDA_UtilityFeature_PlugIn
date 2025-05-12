
// IDA Pro persistent plug-in that adds some helpful utility "missing" commands
// By: Sirmabus 2014, updated 1/2025
#include "StdAfx.h"
#include "resource.h"

#include <algorithm>
#include <vector>


// From SDK "bytes.hpp"
const UINT32 FF_REF  = 0x00001000; // has references
const UINT32 FF_NAME = 0x00004000; // Has name ?
const UINT32 FF_LABL = 0x00008000; // Has dummy name?

// run(cmd)
enum COMMAND
{
    CMD_FindNextXRef  = 1, // Next address with an xref label
    CMD_FindPrevXRef  = 2, // Previous address with an xref label
    CMD_FindNextNotZ  = 3, // Next address not zeros
    CMD_FindPrevNotZ  = 4, // Previous address not zeros
    CMD_SetDataDwords = 5, // Set at current address run of DWORDs
    CMD_SetDataQwords = 6, // Set at current address run of QWORDs
    CMD_StubRenamer   = 7, // Automatically names common short function stubs for clarity. (from formerly the " Stub Namer plug-in")
};

static BOOL  bearchedForSortFunc  = FALSE;
static BOOL  autoSortDisableTogle = FALSE;
static PVOID idaSortFunction = NULL;
static HMODULE myModule = NULL;

extern void RunStubNamer();


// ======================================================================================
static plugmod_t* idaapi init()
{
	qstring version;
	msg("\n>> Sirmabus utility feature: v%s, built %s.", GetVersionString(MY_VERSION, version).c_str(), __DATE__);
    
    GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) &init, &myModule);       
    return PLUGIN_KEEP;
}

// ======================================================================================
static void idaapi term()
{
    // Make sure WAV clips are terminated before returning
    if(myModule)	
        PlaySound(NULL, 0, 0);
}

// ======================================================================================

static void clickSound()
{
    if(myModule)
        PlaySound(MAKEINTRESOURCE(IDR_WAVE1), myModule, (SND_RESOURCE | SND_ASYNC));
}

static void errorSound()
{
    if(myModule)
        PlaySound(MAKEINTRESOURCE(IDR_WAVE2), myModule, (SND_RESOURCE | SND_ASYNC));
}

// --------------------------------------------------------------------------------------

bool idaapi run(size_t cmd)
{
    plat.Configure();

    //msg("cmd: %d\n", cmd);
    switch(cmd)
    {
        // FindNextXRef
        // Jump forward to the next line with an xref or a label
        case CMD_FindNextXRef:
        {
            BOOL bSuccess = FALSE;
            ea_t eaScreen = get_screen_ea();            
            if(eaScreen != BADADDR)
            {
                while((eaScreen = next_addr(eaScreen)) != BADADDR)
                {                   
                    if(get_flags(eaScreen) & (FF_REF | FF_NAME | FF_LABL))
                    {                        
                        jumpto(eaScreen, -1);
                        bSuccess = TRUE;
                        break;
                    }
                };
            }     

            if(bSuccess)
                clickSound();
            else
                errorSound(); 
        }
        break;       

        // FindPrevXRef
        // Jump backwards to the previous line with an xref or label
        case CMD_FindPrevXRef:
        {
            BOOL bSuccess = FALSE;
            ea_t eaScreen = get_screen_ea();            
            if(eaScreen != BADADDR)
            {
                while((eaScreen = prev_addr(eaScreen)) != BADADDR)
                {                   
                    if(get_flags(eaScreen) & (FF_REF | FF_NAME | FF_LABL))
                    {                        
                        jumpto(eaScreen, -1);
                        bSuccess = TRUE;
                        break;
                    }                
                };
            }

            if(bSuccess)
                clickSound();
            else
                errorSound(); 
        }
        break;
       
        // Find the next data value address forward that is not zero
        case CMD_FindNextNotZ:
        {
            BOOL bSuccess = FALSE;
            ea_t eaAddr = get_screen_ea();            
            if(eaAddr != BADADDR)
            {            
                while((eaAddr = next_visea(eaAddr)) != BADADDR)
                {                  
                    // Test typical BYTE to QWORD size values
                    asize_t size = get_item_size(eaAddr);
                    if(size <= sizeof(UINT32))
                    {
                        uval_t v = 0;
                        if(get_data_value(&v, eaAddr, size))
                        {
                            if(v != 0)
                            {
                                jumpto(eaAddr, -1);
                                bSuccess = TRUE;                            
                                break;
                            }
                        }
                    }
                    else
                    // Test odd size block value
                    if(PVOID pBuffer = _aligned_malloc(size, 32))
                    {
                        if(get_bytes(pBuffer, size, eaAddr, GMB_READALL))
                        {
                            PBYTE p = (PBYTE) pBuffer;
                            while(size--)
                            {
                                if(*p++)
                                {
                                    bSuccess = TRUE;
                                    break;
                                }
                            };
                        }
                        _aligned_free(pBuffer);

                        if(bSuccess)
                        {
                            jumpto(eaAddr, -1);                                            
                            break;
                        }
                    }                                                        
                };
            }     

            if(bSuccess)
                clickSound();
            else
                errorSound();   
        }
        break;

        // Find the previous data value address that is not zero
        case CMD_FindPrevNotZ:
        {
            BOOL bSuccess = FALSE;
            ea_t eaAddr = get_screen_ea();            
            if(eaAddr != BADADDR)
            {            
                while((eaAddr = prev_visea(eaAddr)) != BADADDR)
                {                     
                    asize_t size = get_item_size(eaAddr);
                    if(size <= sizeof(UINT32))
                    {
                        uval_t v = 0;
                        if(get_data_value(&v, eaAddr, size))
                        {
                            if(v != 0)
                            {
                                jumpto(eaAddr, -1);
                                bSuccess = TRUE;                            
                                break;
                            }
                        }
                    }
                    else                   
                    if(PVOID pBuffer = _aligned_malloc(size, 32))
                    {
                        if(get_bytes(pBuffer, size, eaAddr))
                        {
                            PBYTE p = (PBYTE) pBuffer;
                            while(size--)
                            {
                                if(*p++)
                                {
                                    bSuccess = TRUE;
                                    break;
                                }
                            };
                        }
                        _aligned_free(pBuffer);

                        if(bSuccess)
                        {
                            jumpto(eaAddr, -1);                                            
                            break;
                        }
                    }                                                        
                };
            }     

            if(bSuccess)
                clickSound();
            else
                errorSound();   
        }
        break;

        // Fill data space with DWORDs
        case CMD_SetDataDwords:
        {
            BOOL success = FALSE;
            ea_t eaScreen = get_screen_ea();            
            if(eaScreen != BADADDR)
            {                      
                // Don't allow fill operation over code
                if(!is_code(get_flags(eaScreen)))
                {
                    // Walk backward to find start of selection
                    ea_t eaStart = BADADDR, eaLast = BADADDR, eaWalk = eaScreen;               
                    do 
                    {
                        flags64_t flags = get_flags(eaWalk);                          
                        if((flags & (FF_REF | FF_NAME | FF_LABL)) || is_code(flags))                  
                        {
                            eaStart = eaWalk;
                            break;
                        }
                        else
                        {
                            eaLast = eaWalk;
                            eaWalk = prev_visea(eaWalk);
                        }

                    } while(eaWalk != BADADDR);

                    // Use last good address, we are probably at the top of the segment
                    // TODO: We could check the segment bounds if this is wrong
                    if(eaStart == BADADDR)
                        eaStart = eaLast;

                    // Should be at align 4
                    if((eaStart & (4 -1)) == 0)
                    {                        
                        // Walk forward past the screen address to find the end of the section
                        ea_t eaEnd = BADADDR;
                        if(eaStart != BADADDR)
                        {
                            ea_t eaWalk = next_visea(eaScreen); 
                            ea_t eaLast = eaWalk;

                            do 
                            {
                                flags64_t flags = get_flags(eaWalk);                              
                                if((flags & (FF_REF | FF_NAME | FF_LABL)) || is_code(flags))                    
                                {
                                    eaEnd = eaWalk;
                                    break;
                                }
                                else
                                {
                                    eaLast = eaWalk;
                                    eaWalk = next_visea(eaWalk);
                                }

                            } while(eaWalk != BADADDR);                   
                        }

                        // Found our extents, now fill
                        if(((eaStart != BADADDR) && (eaEnd != BADADDR)) && ((eaEnd - eaScreen) >= sizeof(UINT32)))
                        {
                            UINT32 count = (UINT32) ((eaEnd - eaStart) / sizeof(UINT32));
                            msg("Utility: DWORD fill: %llX to %llX, count: %u\n", eaStart, eaEnd, count);
                            while(count--){ create_dword(eaStart, sizeof(UINT32)); eaStart += sizeof(UINT32); };
                            success = TRUE;
                        }  

                    }
                    else
                        msg("Utility: ** Start address %014llX <click me> is not align 4, aborted. **\n", eaStart);
                }               
                else
                    msg("Utility: ** Code here!, aborted. **\n");                
            }          

            if(success)
                clickSound();
            else
                errorSound(); 
            refresh_idaview_anyway();
        }
        break;

        // Fill data space with QWORDs
        case CMD_SetDataQwords:
        {
            BOOL success = FALSE;
            ea_t eaScreen = get_screen_ea();            
            if(eaScreen != BADADDR)
            {                      
                // Don't allow fill operation over code
                if(!is_code(get_flags(eaScreen)))
                {
                    // Walk backward to find start of selection
                    ea_t eaStart = BADADDR, eaLast = BADADDR, eaWalk = eaScreen;               
                    do 
                    {
                        flags64_t flags = get_flags(eaWalk);                          
                        if((flags & (FF_REF | FF_NAME | FF_LABL)) || is_code(flags))                  
                        {
                            eaStart = eaWalk;
                            break;
                        }
                        else
                        {
                            eaLast = eaWalk;
                            eaWalk = prev_visea(eaWalk);
                        }

                    } while(eaWalk != BADADDR);

                    // Use last good address, we are probably at the top of the segment
                    // TODO: We could check the segment bounds if this is wrong
                    if(eaStart == BADADDR)
                        eaStart = eaLast;

                    // Should be at align 8
                    if((eaStart & (8 - 1)) == 0)
                    {                        
                        // Walk forward past the screen address to find the end of the section
                        ea_t eaEnd = BADADDR;
                        if(eaStart != BADADDR)
                        {
                            ea_t eaWalk = next_visea(eaScreen); 
                            ea_t eaLast = eaWalk;

                            do 
                            {
                                flags64_t flags = get_flags(eaWalk);                              
                                if((flags & (FF_REF | FF_NAME | FF_LABL)) || is_code(flags))                    
                                {
                                    eaEnd = eaWalk;
                                    break;
                                }
                                else
                                {
                                    eaLast = eaWalk;
                                    eaWalk = next_visea(eaWalk);
                                }

                            } while(eaWalk != BADADDR);                   
                        }

                        // Found our extents, now fill
                        if(((eaStart != BADADDR) && (eaEnd != BADADDR)) && ((eaEnd - eaScreen) >= sizeof(UINT32)))
                        {
                            UINT32 count = (UINT32) ((eaEnd - eaStart) / sizeof(UINT64));
                            msg("Utility: QWORD fill: %014llX to %014llX, count: %u\n", eaStart, eaEnd, count);
                            while (count--){ create_qword(eaStart, sizeof(UINT64)); eaStart += sizeof(UINT64); };
                            success = TRUE;
                        }  

                    }
                    else
                        msg("Utility: ** Start address %014llX <click me> is not align 8, aborted. **\n", eaStart);
                }               
                else
                    msg("Utility: ** Code here!, aborted. **\n");                
            }          

            if(success)
                clickSound();
            else
                errorSound(); 
            refresh_idaview_anyway();
        }
        break;

        // Run the function stub renamer
        case CMD_StubRenamer:
        {
            msg("Utility: Running Stub namer:\n");
            RunStubNamer();
        }
        break;
		
        default:
        {
            //msg("===========================================================================\n");
            //msg(szHelp);
            errorSound();
        }
        break;
    };  

	return true;
}


// ======================================================================================

const static char name[] = { "Sirmabus utility feature" };

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX,
    init,
    term,
    run,
    name,
    name,
    name,
    NULL
};
