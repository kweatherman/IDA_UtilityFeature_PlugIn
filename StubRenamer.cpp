
// Automatically names common short function stubs for clarity.
// Formerly the "IDA_StubNamer_PlugIn" 
// By: Sirmabus 2009, updated 1/2025
#include "StdAfx.h"
#include <WaitBoxEx.h>
#include <vector>

#define MAX_PATTERN_LINES 2

// Text pattern container
struct PATERN
{
	LPCSTR* patern; // ASM text line(s) of the pattern
	int     count;  // Count of lines text lines
	PUINT   pcount; // Ref to track stats
	LPCSTR  format; // Stub name format text
};
typedef std::vector<PATERN> PATTERNS;

static UINT s_zeroIndex = 0, s_falseIndex = 0, s_TRUEIndex = 0, s_trueIndex = 0, s_fzeroIndex = 0, s_nullIndex = 0;
#define TOTAL_NAMES_STATS (s_zeroIndex + s_falseIndex + s_TRUEIndex + s_trueIndex + s_nullIndex)

/*
	Patterns:

	return(NULL)/return(0)/return(FALSE)
	return(false)
	return(TRUE)
	return(true)

	return((float) 0)
*/

// TODO: (Big) Make a batch Python script and run it over a corpus of IDBs both 32 and 64 bit


static void processFunction(func_t *f, PATTERNS &patterns);

// Build text disasm search patterns
static void BuildPatterns(PATTERNS &patterns)
{
	// Return 0/NULL/FALSE
	static const LPCSTR retZero_32[] =
	{
		"xor     eax, eax",
		"sub     eax, eax",
		"mov     eax, 0",
		"mov     ax, 0",				
	};
	static const LPCSTR retZero_64[] =
	{				
		"xor     rax, rax",
		"sub     rax, rax",
		"mov     rax, 0",				
	};

	// Return bool false
	static const LPCSTR retFalse[] =
	{
		"xor     al, al",
		"sub     al, al",
		"mov     al, 0",
	};

	// Return BOOL TRUE
	static const LPCSTR retTRUE_32[] =
	{
		"mov     eax, 1",			
	};
	static const LPCSTR retTRUE_64[] =
	{			
		"mov     rax, 1",				
	};

	// Return bool true
	static const LPCSTR retTrue[] =
	{
		"mov     al, 1",
	};

	// Return floating point zero
	static const LPCSTR retFZero_32[] =
	{
		"fldz",				
	};
	static const LPCSTR retFZero_64[] =
	{			
		"psrldq  xmm0, 0",
	};
	
	patterns.push_back({ (LPCSTR*) retTrue,  _countof(retTrue),  &s_trueIndex,  "trueSub_%u" });
	patterns.push_back({ (LPCSTR*) retFalse, _countof(retFalse), &s_falseIndex, "falseSub_%u" });

	if (!plat.is64)
	{
		// 32bit
		patterns.push_back({ (LPCSTR*) retZero_32,  _countof(retZero_32),  &s_zeroIndex,  "zeroSub_%u" });
		patterns.push_back({ (LPCSTR*) retTRUE_32,  _countof(retTRUE_32),  &s_TRUEIndex,  "trueSub_%u" });
		patterns.push_back({ (LPCSTR*) retFZero_32, _countof(retFZero_32), &s_fzeroIndex, "fZeroSub_%u" });
	}
	else
	{
		// 64bit
		patterns.push_back({ (LPCSTR*) retZero_64,  _countof(retZero_64),  &s_zeroIndex,  "zeroSub_%u" });
		patterns.push_back({ (LPCSTR*) retTRUE_64,  _countof(retTRUE_64),  &s_TRUEIndex,  "trueSub_%u" });
		patterns.push_back({ (LPCSTR*) retFZero_64, _countof(retFZero_64), &s_fzeroIndex, "fZeroSub_%u" });
	}
}


void RunStubNamer()
{
	WaitBox::show();
	try
	{
		// First build up patterns
		PATTERNS patterns;
		BuildPatterns(patterns);

		// Iterate through all functions..
		TIMESTAMP startTime = GetTimeStamp();
		UINT funcCount = (UINT)get_func_qty();
		char buffer[32];
		msg(" Processing %s functions:\n", NumberCommaString(funcCount, buffer));

		for (UINT n = 0; n < funcCount; n++)
		{
			processFunction(getn_func(n), patterns);

			if (n % 1000)
			{
				if (WaitBox::isUpdateTime())
				{
					if (WaitBox::updateAndCancelCheck((int)(((float)n / (float)funcCount) * 100.0f)))
					{
						msg("* Aborted *\n");
						break;
					}
				}
			}
		}

		msg("Done. Named %s stub functions in %s.\n", NumberCommaString(TOTAL_NAMES_STATS, buffer), TimeString(GetTimeStamp() - startTime));
	}
	CATCH();
	WaitBox::hide();
}


// ======================================================================================

// Return TRUE if address matches pattern
BOOL isOfPatern(LPCSTR lineStr, LPCSTR* pattern, int patternCount)
{
	for (int i = 0; i < patternCount; i++)
	{
		if (strcmp(lineStr, pattern[i]) == 0)
			return(TRUE);
	}
	return(FALSE);
}

// Return TRUE if address is a return opcode
BOOL isReturn(ea_t ea)
{
	insn_t cmd;
	if ((decode_insn(&cmd, ea) > 0) && (cmd.size != 0))
	{
		if ((cmd.itype == NN_retn) || (cmd.itype == NN_retf))
			return TRUE;
	}
	return FALSE;
}


// Process function
static void processFunction(func_t* f, PATTERNS &patterns)
{
	// Quick rejection test
	if (f->does_return() && !is_func_tail(f) && (f->size() <= 10)
		/* Skip if already has a name */
		&& !has_name(get_flags(f->start_ea))
		)
	{
		// 1st pass, check if less than MAX_PATTERN_LINES and the last instruction is a return
		int instLines = 0;
		{
			ea_t currentEA = f->start_ea;
			ea_t endEA = f->end_ea;
			ea_t lastEa = BADADDR;

			while ((instLines <= MAX_PATTERN_LINES) && (currentEA != BADADDR) && (currentEA < endEA))
			{
				instLines++;
				lastEa = currentEA;
				currentEA = next_head(currentEA, endEA);
			};

			if ((instLines <= MAX_PATTERN_LINES) && (instLines > 0))
			{
				if (!isReturn(lastEa))
					return;
			}
			else
				return;
		}

		// Two line patterns
		if (instLines == MAX_PATTERN_LINES)
		{
			// Try each pattern against the line
			qstring str;
			getDisasmText(f->start_ea, str);
			LPCSTR lineStr = str.c_str();
			size_t patternCount = patterns.size();
			for (size_t i = 0; i < patternCount; i++)
			{
				ea_t currentEA = f->start_ea;
				if (isOfPatern(lineStr, patterns[i].patern, patterns[i].count))
				{
					// Create name
					// Normally starts at the last count, but serialize until we find one not used
					// if we have to.					
					LPCSTR format = patterns[i].format;
					UINT   startSeq = *patterns[i].pcount;
					char name[32]; name[SIZESTR(name)] = 0;
					for (UINT j = startSeq; j < 0xFFFF; j++)
					{
						sprintf(name, format, j);
						if (set_name(f->start_ea, name, (SN_NON_AUTO | SN_NOLIST | SN_NOWARN)))
						{
							*patterns[i].pcount += 1;
							return;
						}
					}

					msg("%llX ** Failed to set stub name: \"%s\" ** <Click Me>\n", f->start_ea, name);
					return;
				}
			}
		}
		else
		// Do nothing return stub?
		if (instLines == 1)
		{
			char name[32]; name[SIZESTR(name)] = 0;
			for (UINT i = 0; i < 0xFFFF; i++)
			{
				sprintf(name, "nullSub_%u", i);
				if (set_name(f->start_ea, name, (SN_NON_AUTO | SN_NOLIST | SN_NOWARN)))
				{
					s_nullIndex++;
					return;
				}
			}
		}
	}
}
