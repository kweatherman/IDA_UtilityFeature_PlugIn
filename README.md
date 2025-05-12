# Utility Feature IDA Pro Plug-In

Kevin Weatherman aka "Sirmabus"
Repo [Github](https://github.com/kweatherman/IDA_UtilityFeature_PlugIn)

Utility plugin to add some additional functionality to IDA.

----

## Introduction

Adds several features that I've added over the years. Mainly for helping with data segments.  
You pretty much have to try them out and see if you find them useful, and you probably will.

Note unlike the majority of the my other plugins, there is no UI at all for this one.  
 It's intended to be operated using configured hotkey command codes. 

## Features

* Jump to next, or previous XREF.   
  Use this to help navigate large data blocks/tables, and large functions too.

* Jump to next, or previous address that is not all zeros.  
  Use when navigating large blocks of data to find when it's not all zeros.

* Set DWORD(s), or QWORD(s) at the current selected address.  
  I end up using this one a lot walking through data segments manually fixing virtual function and other tables.

* Function stub renamer. Particularly useful for large IDBs with lots (like hundreds, if not thousands) of little return FALSE/TRUE/NULL stubs.  

  Can save a lot of time avoiding looking at the same simple return stubs over and over again.  
  **TODO: Based on code patterns and could use more. Make an MR with your added patterns and I'll merge them into the repo.**

## Installation

1) Copy the plugin to your IDA Pro plugins directory.
2) You'll want at least the first six features on hotkeys.  
   I add this to my "plugins.cfg" like this:

```ini
; Utility plug-in
FindNextXRef  IDA_UtilityFeature   ] 1 WIN
FindPrevXRef  IDA_UtilityFeature   [ 2 WIN
FindNextNotZ  IDA_UtilityFeature   , 3 WIN
FindPrevNotZ  IDA_UtilityFeature   . 4 WIN
SetDataDwords IDA_UtilityFeature   Ctrl-D 5 WIN
SetDataQwords IDA_UtilityFeature   Alt-D 6 WIN
StubNamer     IDA_UtilityFeature   Alt-3 7 WIN
```

But first you will need to edit your "idagui.cfg" config file and disable some of the default hot keys to avoid conflicts. Or obviously just use ones not taken up by IDA.  
Make these mods (search for each key combo): 

```ini
"JumpData": [0], //["Ctrl-D"],
"TracingDiffToggle": [0], //["Ctrl-D"], // Toggle diff
"SetupData": [0], //["Alt-D"],
"WindowActivate3": [0], //["Alt-3"],
```

I usually disable the majority of the "Alt" and "Ctrl" number key combos, and most of the function key ones too for use as plugin hotkeys.



----

##### License

**MIT License**
Copyright © 2025 Kevin Weatherman  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

See [MIT License](http://www.opensource.org/licenses/mit-license.php) for full details.