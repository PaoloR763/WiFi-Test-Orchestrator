$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Get-InterfaceIndex {
    param([object]$Item)

    if ($null -ne $Item.ifIndex) {
        return [int]$Item.ifIndex
    }
    return [int]$Item.InterfaceIndex
}

function ConvertTo-AddressFamilyName {
    param([object]$Value)

    switch ([string]$Value) {
        { $_ -in @('2', 'IPv4', 'InterNetwork') } { return 'IPv4' }
        { $_ -in @('23', 'IPv6', 'InterNetworkV6') } { return 'IPv6' }
        default { return $null }
    }
}

function Add-IndexedValue {
    param(
        [hashtable]$Index,
        [int]$Key,
        [object]$Value
    )

    if ($Index.ContainsKey($Key)) {
        $Index[$Key] = @($Index[$Key]) + @($Value)
    } else {
        $Index[$Key] = @($Value)
    }
}

# Each fixed provider runs in its own explicit child PowerShell process. A ready
# event proves that the child reached its barrier; the query cannot run until the
# coordinator releases the separate start event after native Job containment.
# Setup is measured separately from the 20 second provider phase. The coordinator
# uses a 26 second planning window beneath the hard external 30 second process
# watchdog and reserves the maximum provider budget, cleanup, and assembly.
$providerDefinitions = @(
    [pscustomobject]@{
        Key = 'drivers'
        Name = 'Win32_PnPSignedDriver'
        TimeoutMilliseconds = 8000
        Query = {
            Get-CimInstance -ClassName Win32_PnPSignedDriver `
                -Property DeviceID, Manufacturer, DeviceName, DriverProviderName, DriverVersion `
                -OperationTimeoutSec 8 -ErrorAction Stop
        }
    },
    [pscustomobject]@{
        Key = 'adapters'
        Name = 'Get-NetAdapter'
        TimeoutMilliseconds = 8000
        Query = {
            Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object -Property ifIndex
        }
    },
    [pscustomobject]@{
        Key = 'statistics'
        Name = 'Get-NetAdapterStatistics'
        TimeoutMilliseconds = 5000
        Query = {
            Get-NetAdapterStatistics -IncludeHidden -ErrorAction Stop
        }
    },
    [pscustomobject]@{
        Key = 'ip_configuration'
        Name = 'Get-NetIPConfiguration'
        TimeoutMilliseconds = 10000
        Query = {
            Get-NetIPConfiguration -ErrorAction Stop
        }
    },
    [pscustomobject]@{
        Key = 'addresses'
        Name = 'Get-NetIPAddress'
        TimeoutMilliseconds = 5000
        Query = {
            Get-NetIPAddress -ErrorAction Stop
        }
    },
    [pscustomobject]@{
        Key = 'routes'
        Name = 'Get-NetRoute'
        TimeoutMilliseconds = 5000
        Query = {
            Get-NetRoute -ErrorAction Stop
        }
    },
    [pscustomobject]@{
        Key = 'dns'
        Name = 'Get-DnsClientServerAddress'
        TimeoutMilliseconds = 5000
        Query = {
            Get-DnsClientServerAddress -ErrorAction Stop
        }
    }
)

$diagnosticsEnabled = $env:WTO_INVENTORY_DIAGNOSTICS -eq '1'
$coordinatorTimeoutMilliseconds = 26000
$providerPhaseTimeoutMilliseconds = 20000
$providerStartupTimeoutMilliseconds = 5000
$markerDeliveryGraceMilliseconds = 100
$providerCleanupTimeoutMilliseconds = 3000
$providerFinalCleanupTimeoutMilliseconds = 1000
$inventoryAssemblyReserveMilliseconds = 1000
$outerWatchdogReserveMilliseconds = 1000
$outerTimeoutMilliseconds = 30000
$configuredOuterTimeoutMilliseconds = 0
if (
    [int]::TryParse(
        [string]$env:WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS,
        [ref]$configuredOuterTimeoutMilliseconds
    ) -and
    $configuredOuterTimeoutMilliseconds -ge 10000 -and
    $configuredOuterTimeoutMilliseconds -le 120000
) {
    $outerTimeoutMilliseconds = $configuredOuterTimeoutMilliseconds
}
$coordinatorStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$maximumProviderTimeoutMilliseconds = [int](
    $providerDefinitions |
        Measure-Object -Property TimeoutMilliseconds -Maximum |
        Select-Object -ExpandProperty Maximum
)
$requiredPostReleaseMilliseconds = (
    $maximumProviderTimeoutMilliseconds +
    $providerCleanupTimeoutMilliseconds +
    $providerFinalCleanupTimeoutMilliseconds
)
$providerStates = @()

function Initialize-WtoInventoryNativeProcess {
    if ($null -ne ('WtoInventoryProcessHandle' -as [type])) { return }
    $nativeProcessSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public enum WtoInventoryTerminationResult
{
    TerminationRequested,
    AlreadyExited
}

public sealed class WtoInventoryProcessHandle : IDisposable
{
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorMoreData = 234;
    private const int JobObjectBasicAccountingInformationClass = 1;
    private const int JobObjectBasicProcessIdListClass = 3;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private SafeProcessHandle handle;
    private SafeFileHandle providerJob;
    private List<SafeProcessHandle> cleanupProcessHandles = new List<SafeProcessHandle>();

    private WtoInventoryProcessHandle(
        SafeProcessHandle stableHandle,
        int processId,
        SafeFileHandle stableProviderJob
    )
    {
        handle = stableHandle;
        providerJob = stableProviderJob;
        ProcessId = processId;
        int actualProcessId = unchecked((int)GetProcessId(handle));
        if (actualProcessId != processId)
        {
            throw new InvalidOperationException("process identity changed while opening stable handle");
        }
        CreationFileTimeUtc = ReadCreationFileTime(handle);
        ImageName = ReadImageName(handle);
    }

    public int ProcessId { get; private set; }
    public long CreationFileTimeUtc { get; private set; }
    public string ImageName { get; private set; }
    public bool IsPowerShell
    {
        get
        {
            string name = Path.GetFileName(ImageName);
            return string.Equals(name, "powershell.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "pwsh.exe", StringComparison.OrdinalIgnoreCase);
        }
    }

    public static WtoInventoryProcessHandle OpenForProcess(Process process)
    {
        if (process == null) { throw new ArgumentNullException("process"); }

        SafeProcessHandle stableHandle = DuplicateProcessHandle(process);
        WtoInventoryProcessHandle result = null;
        try
        {
            result = new WtoInventoryProcessHandle(stableHandle, process.Id, null);
            result.AttachProviderJob();
            return result;
        }
        catch
        {
            if (result != null) { result.Dispose(); }
            else { stableHandle.Dispose(); }
            throw;
        }
    }

    public bool ValidateMarker(int processId, long creationFileTimeUtc)
    {
        ThrowIfDisposed();
        return ProcessId == processId && CreationFileTimeUtc == creationFileTimeUtc;
    }

    public bool IsExited
    {
        get
        {
            ThrowIfDisposed();
            uint result = WaitForSingleObject(handle, 0);
            if (result == WaitObject0) { return true; }
            if (result == WaitTimeout) { return false; }
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed");
        }
    }

    public bool HasActiveProcesses
    {
        get
        {
            ThrowIfDisposed();
            if (providerJob == null || providerJob.IsInvalid) { return !IsExited; }
            JobObjectBasicAccountingInformation accounting;
            uint returnedLength;
            if (!QueryInformationJobObject(
                providerJob,
                JobObjectBasicAccountingInformationClass,
                out accounting,
                (uint)Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation)),
                out returnedLength
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryInformationJobObject failed"
                );
            }
            return accounting.ActiveProcesses != 0;
        }
    }

    public bool AllKnownProcessesExited
    {
        get
        {
            ThrowIfDisposed();
            if (!IsExited) { return false; }
            foreach (SafeProcessHandle processHandle in cleanupProcessHandles)
            {
                if (!IsHandleSignaled(processHandle)) { return false; }
            }
            return true;
        }
    }

    public WtoInventoryTerminationResult Terminate()
    {
        ThrowIfDisposed();
        bool alreadyExited = IsExited;
        Exception processError = null;
        if (!alreadyExited && !TerminateProcess(handle, 1))
        {
            int error = Marshal.GetLastWin32Error();
            if (!IsExited) { processError = new Win32Exception(error, "TerminateProcess failed"); }
        }
        if (providerJob != null && !providerJob.IsInvalid && !TerminateJobObject(providerJob, 1))
        {
            int error = Marshal.GetLastWin32Error();
            if (HasActiveProcesses)
            {
                throw new Win32Exception(error, "TerminateJobObject failed");
            }
        }
        if (processError != null) { throw processError; }
        return alreadyExited
            ? WtoInventoryTerminationResult.AlreadyExited
            : WtoInventoryTerminationResult.TerminationRequested;
    }

    public void CloseProviderJobForCleanup()
    {
        ThrowIfDisposed();
        if (providerJob == null) { return; }

        Exception primaryError = null;
        List<SafeProcessHandle> capturedHandles = new List<SafeProcessHandle>();
        try
        {
            // Capture wait-only descendant handles while the Job handle is valid.
            // Membership is checked by CaptureJobProcessHandles; a reused PID is
            // discarded and can never become a termination target.
            capturedHandles.AddRange(CaptureJobProcessHandles());
        }
        catch (Exception error)
        {
            primaryError = error;
        }
        try
        {
            if (HasActiveProcesses && !TerminateJobObject(providerJob, 1))
            {
                int error = Marshal.GetLastWin32Error();
                if (HasActiveProcesses)
                {
                    throw new Win32Exception(error, "TerminateJobObject failed during cleanup");
                }
            }
        }
        catch (Exception error)
        {
            if (primaryError == null) { primaryError = error; }
        }
        try
        {
            // A descendant may have appeared after the first snapshot but before
            // TerminateJobObject. Capture a second wait-only snapshot before the
            // Job handle is closed; closing still supplies the race-free kill.
            capturedHandles.AddRange(CaptureJobProcessHandles());
        }
        catch (Exception error)
        {
            if (primaryError == null) { primaryError = error; }
        }

        cleanupProcessHandles.AddRange(capturedHandles);
        providerJob.Dispose();
        providerJob = null;
        if (primaryError != null) { throw primaryError; }
    }

    public void Dispose()
    {
        if (providerJob != null)
        {
            providerJob.Dispose();
            providerJob = null;
        }
        foreach (SafeProcessHandle processHandle in cleanupProcessHandles)
        {
            processHandle.Dispose();
        }
        cleanupProcessHandles.Clear();
        if (handle != null)
        {
            handle.Dispose();
            handle = null;
        }
    }

    private void AttachProviderJob()
    {
        SafeFileHandle jobHandle = CreateJobObject(IntPtr.Zero, null);
        if (jobHandle == null || jobHandle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (jobHandle != null) { jobHandle.Dispose(); }
            throw new Win32Exception(error, "CreateJobObject failed");
        }
        try
        {
            JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(
                jobHandle,
                JobObjectExtendedLimitInformationClass,
                ref limits,
                (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation))
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetInformationJobObject failed"
                );
            }
            if (!AssignProcessToJobObject(jobHandle, handle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AssignProcessToJobObject failed"
                );
            }
            providerJob = jobHandle;
        }
        catch
        {
            jobHandle.Dispose();
            throw;
        }
    }

    private static SafeProcessHandle DuplicateProcessHandle(Process process)
    {
        SafeProcessHandle source = process.SafeHandle;
        bool referenceAdded = false;
        try
        {
            source.DangerousAddRef(ref referenceAdded);
            IntPtr duplicate;
            if (!DuplicateHandle(
                GetCurrentProcess(),
                source.DangerousGetHandle(),
                GetCurrentProcess(),
                out duplicate,
                0,
                false,
                DuplicateSameAccess
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DuplicateHandle failed"
                );
            }
            return new SafeProcessHandle(duplicate, true);
        }
        finally
        {
            if (referenceAdded) { source.DangerousRelease(); }
        }
    }

    private List<SafeProcessHandle> CaptureJobProcessHandles()
    {
        List<SafeProcessHandle> result = new List<SafeProcessHandle>();
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int capacity = 32;
            while (true)
            {
                int bufferSize = 8 + (capacity * IntPtr.Size);
                buffer = Marshal.AllocHGlobal(bufferSize);
                uint returnedLength;
                if (QueryInformationJobObject(
                    providerJob,
                    JobObjectBasicProcessIdListClass,
                    buffer,
                    (uint)bufferSize,
                    out returnedLength
                ))
                {
                    break;
                }

                int error = Marshal.GetLastWin32Error();
                int assignedProcesses = Marshal.ReadInt32(buffer, 0);
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                if (error != ErrorMoreData || assignedProcesses <= capacity)
                {
                    throw new Win32Exception(error, "QueryInformationJobObject process list failed");
                }
                capacity = assignedProcesses;
            }

            int processCount = Marshal.ReadInt32(buffer, 4);
            for (int index = 0; index < processCount; index++)
            {
                long rawProcessId = IntPtr.Size == 8
                    ? Marshal.ReadInt64(buffer, 8 + (index * IntPtr.Size))
                    : Marshal.ReadInt32(buffer, 8 + (index * IntPtr.Size));
                int processId = unchecked((int)rawProcessId);
                if (processId == ProcessId) { continue; }

                SafeProcessHandle processHandle = OpenProcess(
                    ProcessQueryLimitedInformation | Synchronize,
                    false,
                    processId
                );
                if (processHandle == null || processHandle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (processHandle != null) { processHandle.Dispose(); }
                    if (error == ErrorInvalidParameter) { continue; }
                    throw new Win32Exception(error, "OpenProcess for cleanup wait failed");
                }

                bool belongsToProviderJob;
                int actualProcessId = unchecked((int)GetProcessId(processHandle));
                if (!IsProcessInJob(processHandle, providerJob, out belongsToProviderJob))
                {
                    int error = Marshal.GetLastWin32Error();
                    processHandle.Dispose();
                    throw new Win32Exception(error, "IsProcessInJob failed");
                }
                if (actualProcessId != processId || !belongsToProviderJob)
                {
                    processHandle.Dispose();
                    continue;
                }
                result.Add(processHandle);
            }
            return result;
        }
        catch
        {
            foreach (SafeProcessHandle processHandle in result) { processHandle.Dispose(); }
            throw;
        }
        finally
        {
            if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static bool IsHandleSignaled(SafeProcessHandle processHandle)
    {
        uint result = WaitForSingleObject(processHandle, 0);
        if (result == WaitObject0) { return true; }
        if (result == WaitTimeout) { return false; }
        throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed");
    }

    private void ThrowIfDisposed()
    {
        if (handle == null) { throw new ObjectDisposedException("WtoInventoryProcessHandle"); }
    }

    private static long ReadCreationFileTime(SafeProcessHandle stableHandle)
    {
        FileTime creation;
        FileTime exit;
        FileTime kernel;
        FileTime user;
        if (!GetProcessTimes(stableHandle, out creation, out exit, out kernel, out user))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed");
        }
        return unchecked(((long)creation.High << 32) | creation.Low);
    }

    private static string ReadImageName(SafeProcessHandle stableHandle)
    {
        StringBuilder image = new StringBuilder(32768);
        int length = image.Capacity;
        if (!QueryFullProcessImageName(stableHandle, 0, image, ref length))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageName failed");
        }
        return image.ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle process,
        out FileTime creation,
        out FileTime exit,
        out FileTime kernel,
        out FileTime user
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        int flags,
        StringBuilder image,
        ref int length
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        IntPtr sourceHandle,
        IntPtr targetProcess,
        out IntPtr targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inherit,
        uint options
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObject(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        out JobObjectBasicAccountingInformation information,
        uint informationLength,
        out uint returnedLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnedLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        SafeFileHandle job,
        SafeProcessHandle process
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(
        SafeProcessHandle process,
        SafeFileHandle job,
        [MarshalAs(UnmanagedType.Bool)] out bool result
    );
}
'@
    Add-Type -TypeDefinition $nativeProcessSource -ErrorAction Stop
}

Initialize-WtoInventoryNativeProcess
$internalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Test-ProviderReleaseBudgetAvailable {
    param([bool]$IncludeProviderPhase = $true)

    $providerPhaseAvailable = (
        -not $IncludeProviderPhase -or
        $internalStopwatch.Elapsed.TotalMilliseconds +
            $requiredPostReleaseMilliseconds -le $providerPhaseTimeoutMilliseconds
    )
    return (
        $coordinatorStopwatch.Elapsed.TotalMilliseconds +
            $requiredPostReleaseMilliseconds +
            $inventoryAssemblyReserveMilliseconds -le $coordinatorTimeoutMilliseconds -and
        $coordinatorStopwatch.Elapsed.TotalMilliseconds +
            $requiredPostReleaseMilliseconds +
            $inventoryAssemblyReserveMilliseconds +
            $outerWatchdogReserveMilliseconds -le $outerTimeoutMilliseconds -and
        $providerPhaseAvailable
    )
}

function Write-ProviderDiagnostic {
    param([object]$State)

    if (-not $diagnosticsEnabled -or $State.DiagnosticEmitted) { return }
    $elapsedMilliseconds = [int64](
        $State.FinishedMilliseconds - $State.StartedMilliseconds
    )
    $diagnosticValues = @(
        $State.Definition.Name
        $State.Status
        $elapsedMilliseconds
        $State.Definition.TimeoutMilliseconds
        @($State.Result).Count
        $State.Termination
        $State.WorkerStateAtFinish
    )
    [Console]::Error.WriteLine((
        'wto_inventory provider={0} status={1} elapsed_ms={2} timeout_ms={3} items={4} termination={5} worker_state={6}' -f
            $diagnosticValues
    ))
    $State.DiagnosticEmitted = $true
}

function New-ProviderWorkerCommand {
    param(
        [object]$Definition,
        [string]$StartEventName,
        [string]$ReadyEventName
    )

    # This template and every inserted query originate from the fixed local
    # provider allowlist above. No server data, arguments, paths, or downloaded
    # script can reach the encoded child command.
    $workerTemplate = @'
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$startEvent = $null
$readyEvent = $null
try {
    $startEvent = [Threading.EventWaitHandle]::OpenExisting('__WTO_START_EVENT__')
    $readyEvent = [Threading.EventWaitHandle]::OpenExisting('__WTO_READY_EVENT__')
    $worker = [Diagnostics.Process]::GetCurrentProcess()
    $marker = '{0}|{1}' -f @(
        $PID
        $worker.StartTime.ToUniversalTime().ToFileTimeUtc()
    )
    [Console]::Out.WriteLine($marker)
    [Console]::Out.Flush()
    $null = $readyEvent.Set()
    $null = $startEvent.WaitOne()
    try {
        $providerResult = @(
            & {
__WTO_FIXED_QUERY__
            }
        )
        $payload = [pscustomobject]@{
            Success = $true
            Result = $providerResult
        }
    } catch {
        $payload = [pscustomobject]@{
            Success = $false
            Result = @()
        }
    }
    $serialized = [Management.Automation.PSSerializer]::Serialize($payload, 8)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($serialized))
    [Console]::Out.Write($encoded)
} catch {
    [Environment]::ExitCode = 2
} finally {
    if ($null -ne $readyEvent) { $readyEvent.Dispose() }
    if ($null -ne $startEvent) { $startEvent.Dispose() }
}
'@
    $fixedQuery = [string]$Definition.Query
    return $workerTemplate.Replace('__WTO_START_EVENT__', $StartEventName).
        Replace('__WTO_READY_EVENT__', $ReadyEventName).
        Replace('__WTO_FIXED_QUERY__', $fixedQuery)
}

function Request-ProviderTermination {
    param([object]$State)

    if (
        $State.TerminationRequested -and
        $State.Termination -in @('already_exited', 'process_handle', 'launch_handle')
    ) { return }
    $State.TerminationRequested = $true
    if ($null -eq $State.WorkerHandle) {
        if ($State.ProcessStarted -and $null -ne $State.Process) {
            if ($State.ProcessObjectTerminationRequested) { return }
            $State.ProcessObjectTerminationRequested = $true
            try {
                if ($State.Process.HasExited) {
                    $State.Termination = 'already_exited'
                } else {
                    # System.Diagnostics.Process retains the handle returned by
                    # Process.Start. Kill never resolves WorkerProcessId again.
                    $State.Process.Kill()
                    $State.Termination = 'process_object_handle'
                }
            } catch {
                $State.Termination = 'process_object_termination_failed'
            }
        } else {
            $State.Termination = 'worker_handle_unavailable'
        }
        return
    }
    try {
        $terminationResult = [string]$State.WorkerHandle.Terminate()
        if ($terminationResult -eq 'AlreadyExited') {
            $State.Termination = 'already_exited'
        } elseif ($State.Ready) {
            $State.Termination = 'process_handle'
        } else {
            $State.Termination = 'launch_handle'
        }
    } catch {
        $State.Termination = 'handle_termination_failed'
    }
}

function Update-ProviderReadyState {
    param([object]$State)

    if ($State.Status -ne 'starting') { return }
    try {
        $readySignaled = $State.ReadyEvent.WaitOne(0)
        if ($readySignaled) {
            $nowMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
            if ($null -eq $State.ReadySignaledMilliseconds) {
                $State.ReadySignaledMilliseconds = $nowMilliseconds
            }
            if ($State.MarkerTask.IsCompleted) {
                Update-ProviderMarker $State
                if ($State.IdentityStatus -eq 'validated' -and -not $State.WorkerHandle.IsExited) {
                    $State.Ready = $true
                    $State.Status = 'ready'
                } else {
                    $State.Status = 'failed'
                    $State.WorkerStateAtFinish = if ($State.IdentityStatus -eq 'validated') {
                        'ExitedDuringValidation'
                    } else {
                        'MarkerRejected'
                    }
                    $State.FinishedMilliseconds = $nowMilliseconds
                    Request-ProviderTermination $State
                }
            } elseif (
                $nowMilliseconds - $State.ReadySignaledMilliseconds -ge
                    $markerDeliveryGraceMilliseconds
            ) {
                # The fixed wrapper flushes its marker before signalling Ready.
                # A signalled Ready with no complete line is therefore invalid;
                # terminate promptly rather than consuming the 5-second startup budget.
                $State.Status = 'timed_out'
                $State.WorkerStateAtFinish = 'MarkerMissing'
                $State.FinishedMilliseconds = $nowMilliseconds
                Request-ProviderTermination $State
            }
        } elseif ($State.WorkerHandle.IsExited) {
            if ($State.MarkerTask.IsCompleted) { Update-ProviderMarker $State }
            $State.Status = 'failed'
            $State.WorkerStateAtFinish = 'ExitedBeforeReady'
            $State.FinishedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
        }
    } catch {
        $State.Status = 'failed'
        $State.WorkerStateAtFinish = 'ReadyCheckFailed'
        $State.FinishedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
        Request-ProviderTermination $State
    }
}

function Update-ProviderMarker {
    param([object]$State)

    if ($State.MarkerObserved -or $null -eq $State.MarkerTask -or -not $State.MarkerTask.IsCompleted) {
        return
    }
    try {
        $marker = [string]$State.MarkerTask.GetAwaiter().GetResult()
        $parts = @($marker -split '\|', 2)
        if ($parts.Count -ne 2) { throw 'provider marker format invalid' }
        $markerProcessId = 0
        $markerCreationFileTime = [int64]0
        if (-not [int]::TryParse($parts[0], [ref]$markerProcessId)) {
            throw 'provider marker pid invalid'
        }
        if (-not [int64]::TryParse($parts[1], [ref]$markerCreationFileTime)) {
            throw 'provider marker creation time invalid'
        }
        $State.WorkerProcessId = $markerProcessId
        $State.WorkerCreationFileTime = $markerCreationFileTime
        if ($State.WorkerHandle.ValidateMarker($markerProcessId, $markerCreationFileTime)) {
            $State.IdentityStatus = 'validated'
            $State.StdoutTask = $State.Process.StandardOutput.ReadToEndAsync()
        } else {
            $State.IdentityStatus = 'identity_mismatch'
            $State.StdoutObserved = $true
        }
    } catch {
        $State.IdentityStatus = 'marker_invalid'
        $State.StdoutObserved = $true
    }
    $State.MarkerObserved = $true
    $State.MarkerTask.Dispose()
    $State.MarkerTask = $null
}

function Update-ProviderStreamTasks {
    param([object]$State)

    if (-not $State.MarkerObserved -and $null -ne $State.MarkerTask -and $State.MarkerTask.IsCompleted) {
        Update-ProviderMarker $State
    }
    if (-not $State.StdoutObserved -and $null -ne $State.StdoutTask -and $State.StdoutTask.IsCompleted) {
        try {
            $stdoutText = [string]$State.StdoutTask.GetAwaiter().GetResult()
            if ($State.Status -eq 'completed_pending_receive' -and $stdoutText.Length -gt 0) {
                $serializedBytes = [Convert]::FromBase64String($stdoutText)
                $serialized = [Text.Encoding]::Unicode.GetString($serializedBytes)
                $payload = [Management.Automation.PSSerializer]::Deserialize($serialized)
                if ([bool]$payload.Success) {
                    $State.Result = @($payload.Result)
                    $State.Available = $true
                    $State.Status = 'completed'
                } else {
                    $State.Status = 'failed'
                }
            } elseif ($State.Status -eq 'completed_pending_receive') {
                $State.Status = 'failed'
            }
        } catch {
            if ($State.Status -eq 'completed_pending_receive') { $State.Status = 'failed' }
        }
        $State.StdoutObserved = $true
        $State.StdoutTask.Dispose()
        $State.StdoutTask = $null
    }

    if (-not $State.StderrObserved -and $null -ne $State.StderrTask -and $State.StderrTask.IsCompleted) {
        try {
            # Observe and discard worker stderr. Provider errors may contain host
            # details and are never forwarded to coordinator diagnostics.
            $null = $State.StderrTask.GetAwaiter().GetResult()
        } catch {}
        $State.StderrObserved = $true
        $State.StderrTask.Dispose()
        $State.StderrTask = $null
    }
}

function Update-ProviderProcessCleanupState {
    param([object]$State)

    if ($null -eq $State.WorkerHandle) {
        if (-not $State.ProcessStarted) {
            $State.WorkerExitedAtCleanup = $true
            $State.WorkerTreeExitedAtCleanup = $true
        } elseif ($null -ne $State.Process) {
            try {
                $State.WorkerExitedAtCleanup = [bool]$State.Process.HasExited
                # A worker which failed before Job attachment never passed the
                # start gate, so it could not execute a provider or create a child.
                $State.WorkerTreeExitedAtCleanup = $State.WorkerExitedAtCleanup
            } catch {
                $State.WorkerExitedAtCleanup = $false
                $State.WorkerTreeExitedAtCleanup = $false
            }
        }
        return
    }
    try {
        $State.WorkerExitedAtCleanup = [bool]$State.WorkerHandle.IsExited
        if ($State.ProviderJobClosed) {
            $State.WorkerTreeExitedAtCleanup = [bool]$State.WorkerHandle.AllKnownProcessesExited
        } else {
            $State.WorkerTreeExitedAtCleanup = -not [bool]$State.WorkerHandle.HasActiveProcesses
        }
    } catch {
        $State.WorkerExitedAtCleanup = $false
        $State.WorkerTreeExitedAtCleanup = $false
    }
}

function Close-ProviderStreams {
    param([object]$State)

    if ($null -eq $State.Process) { return }
    # This is the force-close stage after the normal cleanup grace. Close both
    # redirected pipes even when no reader task was created (for example, an
    # invalid marker) so no Process-owned stream survives the bounded cleanup.
    try { $State.Process.StandardOutput.Close() } catch {}
    try { $State.Process.StandardError.Close() } catch {}
}

function Complete-ProviderWorkers {
    param([object[]]$States)

    $cleanupStartedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
    $coordinatorCleanupLimit = [int64][Math]::Min(
        $cleanupStartedMilliseconds +
            $coordinatorTimeoutMilliseconds -
            $inventoryAssemblyReserveMilliseconds -
            $coordinatorStopwatch.Elapsed.TotalMilliseconds,
        $cleanupStartedMilliseconds +
            $outerTimeoutMilliseconds -
            $inventoryAssemblyReserveMilliseconds -
            $outerWatchdogReserveMilliseconds -
            $coordinatorStopwatch.Elapsed.TotalMilliseconds
    )
    $cleanupDeadline = [int64][Math]::Max(
        $cleanupStartedMilliseconds,
        [Math]::Min(
            $cleanupStartedMilliseconds + $providerCleanupTimeoutMilliseconds,
            [Math]::Min(
                $providerPhaseTimeoutMilliseconds - $providerFinalCleanupTimeoutMilliseconds,
                $coordinatorCleanupLimit - $providerFinalCleanupTimeoutMilliseconds
            )
        )
    )

    foreach ($state in $States) { Request-ProviderTermination $state }

    while ($internalStopwatch.Elapsed.TotalMilliseconds -lt $cleanupDeadline) {
        foreach ($state in $States) {
            Update-ProviderProcessCleanupState $state
            Update-ProviderStreamTasks $state
        }
        $pending = @($States | Where-Object {
            $_.WorkerExitedAtCleanup -ne $true -or
            $_.WorkerTreeExitedAtCleanup -ne $true -or
            -not $_.MarkerObserved -or
            -not $_.StdoutObserved -or
            -not $_.StderrObserved
        })
        if ($pending.Count -eq 0) { break }
        Start-Sleep -Milliseconds 25
    }

    $finalCleanupDeadline = [int64][Math]::Max(
        $cleanupDeadline,
        [Math]::Min(
            $cleanupDeadline + $providerFinalCleanupTimeoutMilliseconds,
            [Math]::Min($providerPhaseTimeoutMilliseconds, $coordinatorCleanupLimit)
        )
    )
    foreach ($state in $States) {
        if ($null -eq $state.WorkerHandle) { continue }
        Request-ProviderTermination $state
        try {
            $state.WorkerHandle.CloseProviderJobForCleanup()
            $state.ProviderJobCleanupVerified = $true
        } catch {
            # Never let later exit polling erase an incomplete Job snapshot or
            # close failure. The stable handles are still disposed below, but
            # diagnostics must remain conservative for this lifecycle.
            $state.ProviderJobCleanupVerified = $false
            $state.WorkerExitedAtCleanup = $false
            $state.WorkerTreeExitedAtCleanup = $false
            if ($state.Termination -ne 'handle_termination_failed') {
                $state.Termination = 'cleanup_handle_close_failed'
            }
        } finally {
            $state.ProviderJobClosed = $true
        }
    }

    foreach ($state in $States) { Close-ProviderStreams $state }
    while ($internalStopwatch.Elapsed.TotalMilliseconds -lt $finalCleanupDeadline) {
        foreach ($state in $States) {
            Update-ProviderProcessCleanupState $state
            Update-ProviderStreamTasks $state
        }
        $pending = @($States | Where-Object {
            -not $_.ProviderJobCleanupVerified -or
            $_.WorkerExitedAtCleanup -ne $true -or
            $_.WorkerTreeExitedAtCleanup -ne $true -or
            -not $_.MarkerObserved -or
            -not $_.StdoutObserved -or
            -not $_.StderrObserved
        })
        if ($pending.Count -eq 0) { break }
        Start-Sleep -Milliseconds 10
    }

    foreach ($state in $States) {
        Close-ProviderStreams $state
        Update-ProviderStreamTasks $state
        Update-ProviderProcessCleanupState $state
        if ($null -eq $state.FinishedMilliseconds) {
            $state.FinishedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
        }
        if ($null -ne $state.WorkerHandle) {
            $state.WorkerHandle.Dispose()
            $state.WorkerHandle = $null
        }
        if ($null -ne $state.Process) {
            try {
                # The Job and pipes have already been force-closed. Dispose the
                # retained launch Process handle even if exit/task observation
                # did not finish inside the explicit 3 s + 1 s cleanup grace.
                $state.Process.Dispose()
                $state.Process = $null
                $state.ProcessDisposed = $true
            } catch {
                $state.ProcessDisposed = $false
            }
        }
        Update-ProviderStreamTasks $state
        if ($null -ne $state.ReadyEvent) {
            $state.ReadyEvent.Dispose()
            $state.ReadyEvent = $null
        }
        if ($null -ne $state.StartEvent) {
            $state.StartEvent.Dispose()
            $state.StartEvent = $null
        }
        $state.CleanupVerified = (
            $state.ProviderJobCleanupVerified -and
            $state.WorkerExitedAtCleanup -eq $true -and
            $state.WorkerTreeExitedAtCleanup -eq $true -and
            $state.MarkerObserved -and
            $state.StdoutObserved -and
            $state.StderrObserved -and
            $state.ProcessDisposed
        )
    }
}

$workerExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
foreach ($definition in $providerDefinitions) {
    $startedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
    $startEvent = $null
    $readyEvent = $null
    $process = $null
    $workerHandle = $null
    $stdoutTask = $null
    $stderrTask = $null
    $markerTask = $null
    $status = 'starting'
    $processDisposed = $false
    $processStarted = $false
    $processObjectTerminationRequested = $false
    $termination = 'none'
    $setupBudgetUnavailable = -not (Test-ProviderReleaseBudgetAvailable $false)
    try {
        if ($setupBudgetUnavailable) { throw 'provider setup budget unavailable' }
        $eventSuffix = '{0}.{1}.{2}' -f @(
            $PID
            $definition.Key
            [guid]::NewGuid().ToString('N')
        )
        $startEventName = 'Local\WTO.Inventory.Start.' + $eventSuffix
        $readyEventName = 'Local\WTO.Inventory.Ready.' + $eventSuffix
        $startEvent = [Threading.EventWaitHandle]::new(
            $false, [Threading.EventResetMode]::ManualReset, $startEventName
        )
        $readyEvent = [Threading.EventWaitHandle]::new(
            $false, [Threading.EventResetMode]::ManualReset, $readyEventName
        )
        $workerCommand = New-ProviderWorkerCommand $definition $startEventName $readyEventName
        $encodedCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($workerCommand)
        )
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $workerExecutable
        $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encodedCommand
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'provider worker did not start' }
        $processStarted = $true
        $markerTask = $process.StandardOutput.ReadLineAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $workerHandle = [WtoInventoryProcessHandle]::OpenForProcess($process)
        if (-not $workerHandle.IsPowerShell) { throw 'provider worker image mismatch' }
    } catch {
        $status = if ($setupBudgetUnavailable) { 'timed_out' } else { 'failed' }
        if ($null -ne $workerHandle) {
            try { $null = $workerHandle.Terminate(); $termination = 'launch_handle' } catch {
                $termination = 'handle_termination_failed'
            }
        } elseif ($processStarted -and $null -ne $process) {
            $processObjectTerminationRequested = $true
            try {
                if ($process.HasExited) {
                    $termination = 'already_exited'
                } else {
                    $process.Kill()
                    $termination = 'process_object_handle'
                }
            } catch {
                $termination = 'process_object_termination_failed'
            }
        }
    }
    $providerStates += [pscustomobject]@{
        Definition = $definition
        Process = $process
        StartedMilliseconds = $startedMilliseconds
        FinishedMilliseconds = if ($status -ne 'starting') { $startedMilliseconds } else { $null }
        Status = $status
        Available = $false
        Result = @()
        WorkerProcessId = if ($null -ne $workerHandle) { $workerHandle.ProcessId } else { $null }
        WorkerHandle = $workerHandle
        WorkerExitedAtCleanup = if (-not $processStarted) { [bool]$true } else { $null }
        WorkerTreeExitedAtCleanup = if (-not $processStarted) { [bool]$true } else { $null }
        WorkerStateAtFinish = if ($setupBudgetUnavailable) {
            'BudgetUnavailable'
        } elseif ($status -eq 'failed') {
            'StartFailed'
        } else {
            $null
        }
        Ready = $false
        ReadySignaledMilliseconds = $null
        Termination = $termination
        TerminationRequested = $termination -ne 'none'
        ProcessObjectTerminationRequested = $processObjectTerminationRequested
        ProcessStarted = $processStarted
        DiagnosticEmitted = $false
        StartEvent = $startEvent
        ReadyEvent = $readyEvent
        MarkerTask = $markerTask
        MarkerObserved = $null -eq $markerTask
        WorkerCreationFileTime = $null
        IdentityStatus = if ($null -eq $markerTask) { 'unavailable' } else { 'pending' }
        StdoutTask = $stdoutTask
        StderrTask = $stderrTask
        StdoutObserved = $null -eq $markerTask
        StderrObserved = $null -eq $stderrTask
        ProviderJobClosed = $false
        ProviderJobCleanupVerified = $null -eq $workerHandle
        ProcessDisposed = $processDisposed -or $null -eq $process
        CleanupVerified = -not $processStarted -and $processDisposed
    }
}

$internalStopwatch.Restart()
foreach ($state in $providerStates) {
    $state.StartedMilliseconds = 0
    if ($state.Status -ne 'starting') { $state.FinishedMilliseconds = 0 }
}

try {
    $startupDeadlineMilliseconds = [int64](
        $internalStopwatch.Elapsed.TotalMilliseconds + $providerStartupTimeoutMilliseconds
    )
    while ($true) {
        foreach ($state in @($providerStates | Where-Object { $_.Status -eq 'starting' })) {
            Update-ProviderReadyState $state
        }
        $pendingReady = @($providerStates | Where-Object { $_.Status -eq 'starting' })
        if (
            $pendingReady.Count -eq 0 -or
            $internalStopwatch.Elapsed.TotalMilliseconds -ge $startupDeadlineMilliseconds -or
            -not (Test-ProviderReleaseBudgetAvailable)
        ) { break }
        Start-Sleep -Milliseconds 10
    }

    $providersStartedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
    $releaseBudgetAvailable = Test-ProviderReleaseBudgetAvailable
    foreach ($state in @($providerStates | Where-Object {
        $_.Status -in @('ready', 'starting')
    })) {
        Update-ProviderReadyState $state
        if (-not $releaseBudgetAvailable -or -not $state.Ready) {
            $state.Status = 'timed_out'
            $state.WorkerStateAtFinish = if ($state.Ready) { 'ReadyNotReleased' } else { 'MarkerMissing' }
            $state.FinishedMilliseconds = $providersStartedMilliseconds
            Request-ProviderTermination $state
        } else {
            $state.StartedMilliseconds = $providersStartedMilliseconds
            $state.Status = 'running'
            $null = $state.StartEvent.Set()
        }
    }

    while (@($providerStates | Where-Object { $_.Status -eq 'running' }).Count -gt 0) {
        foreach ($state in @($providerStates | Where-Object { $_.Status -eq 'running' })) {
            $nowMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
            $elapsedMilliseconds = $nowMilliseconds - $state.StartedMilliseconds
            $workerExited = $false
            try {
                $workerExited = [bool]$state.WorkerHandle.IsExited
            } catch {
                $state.Status = 'failed'
                $state.WorkerStateAtFinish = 'HandleCheckFailed'
                $state.FinishedMilliseconds = $nowMilliseconds
                Request-ProviderTermination $state
                continue
            }
            if ($elapsedMilliseconds -ge $state.Definition.TimeoutMilliseconds) {
                $state.Status = 'timed_out'
                $state.WorkerStateAtFinish = if ($workerExited) { 'ExitedAtDeadline' } else { 'Running' }
                $state.FinishedMilliseconds = $nowMilliseconds
                Request-ProviderTermination $state
            } elseif ($workerExited) {
                $state.Status = 'completed_pending_receive'
                $state.WorkerStateAtFinish = 'Exited'
                $state.FinishedMilliseconds = $nowMilliseconds
            }
        }
        if (@($providerStates | Where-Object { $_.Status -eq 'running' }).Count -gt 0) {
            Start-Sleep -Milliseconds 25
        }
    }
} finally {
    foreach ($state in @($providerStates | Where-Object { $_.Status -eq 'running' })) {
        $state.Status = 'timed_out'
        $state.WorkerStateAtFinish = 'CoordinatorCleanup'
        $state.FinishedMilliseconds = [int64]$internalStopwatch.Elapsed.TotalMilliseconds
        Request-ProviderTermination $state
    }
    Complete-ProviderWorkers $providerStates
}

if ($diagnosticsEnabled) {
    foreach ($state in $providerStates) { Write-ProviderDiagnostic $state }
    $remainingWorkerProcesses = @($providerStates | Where-Object {
        -not $_.CleanupVerified -or
        $_.WorkerExitedAtCleanup -eq $false -or
        $_.WorkerTreeExitedAtCleanup -eq $false
    }).Count
    $cleanupDiagnosticValues = @(
        0
        $remainingWorkerProcesses
        [int64]$coordinatorStopwatch.Elapsed.TotalMilliseconds
    )
    [Console]::Error.WriteLine((
        'wto_inventory cleanup jobs_remaining={0} processes_remaining={1} elapsed_ms={2}' -f
            $cleanupDiagnosticValues
    ))
}

$providerResults = @{}
$providerAvailability = @{}
foreach ($state in $providerStates) {
    $providerResults[$state.Definition.Key] = @($state.Result)
    $providerAvailability[$state.Definition.Key] = [bool]$state.Available
}

$signedDrivers = @($providerResults.drivers)
$netAdapters = @($providerResults.adapters)
$allStatistics = @($providerResults.statistics)
$allIpConfigurations = @($providerResults.ip_configuration)
$allAddresses = @($providerResults.addresses)
$allRoutes = @($providerResults.routes)
$allDnsAddresses = @($providerResults.dns)
$statisticsSourceAvailable = $providerAvailability.statistics
$ipConfigurationSourceAvailable = $providerAvailability.ip_configuration
$addressesSourceAvailable = $providerAvailability.addresses
$routesSourceAvailable = $providerAvailability.routes
$dnsSourceAvailable = $providerAvailability.dns

$driversByDeviceId = @{}
foreach ($driver in $signedDrivers) {
    if ($null -ne $driver.DeviceID -and -not $driversByDeviceId.ContainsKey([string]$driver.DeviceID)) {
        $driversByDeviceId[[string]$driver.DeviceID] = $driver
    }
}

$statisticsByInterfaceIndex = @{}
foreach ($statistics in $allStatistics) {
    $interfaceIndex = Get-InterfaceIndex $statistics
    if (-not $statisticsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $statisticsByInterfaceIndex[$interfaceIndex] = $statistics
    }
}

$ipConfigurationsByInterfaceIndex = @{}
foreach ($ipConfiguration in $allIpConfigurations) {
    $interfaceIndex = Get-InterfaceIndex $ipConfiguration
    if (-not $ipConfigurationsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $ipConfigurationsByInterfaceIndex[$interfaceIndex] = $ipConfiguration
    }
}

$addressesByInterfaceIndex = @{}
foreach ($address in $allAddresses) {
    $family = ConvertTo-AddressFamilyName $address.AddressFamily
    if ($null -eq $family) { continue }
    $interfaceIndex = Get-InterfaceIndex $address
    Add-IndexedValue $addressesByInterfaceIndex $interfaceIndex ([ordered]@{
        family = $family
        address = [string]$address.IPAddress
        prefix_length = [int]$address.PrefixLength
    })
}

$routesByInterfaceIndex = @{}
foreach ($route in $allRoutes) {
    $family = ConvertTo-AddressFamilyName $route.AddressFamily
    if ($null -eq $family) { continue }
    $interfaceIndex = Get-InterfaceIndex $route
    Add-IndexedValue $routesByInterfaceIndex $interfaceIndex ([ordered]@{
        family = $family
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        route_metric = [int]$route.RouteMetric
    })
}

$dnsByInterfaceIndex = @{}
foreach ($dnsAddress in $allDnsAddresses) {
    $interfaceIndex = Get-InterfaceIndex $dnsAddress
    foreach ($serverAddress in @($dnsAddress.ServerAddresses)) {
        Add-IndexedValue $dnsByInterfaceIndex $interfaceIndex ([string]$serverAddress)
    }
}

$adapters = @($netAdapters | ForEach-Object {
    $adapter = $_
    $interfaceIndex = [int]$adapter.ifIndex
    $signedDriver = $null
    if ($null -ne $adapter.PnPDeviceID -and $driversByDeviceId.ContainsKey([string]$adapter.PnPDeviceID)) {
        $signedDriver = $driversByDeviceId[[string]$adapter.PnPDeviceID]
    }
    $statistics = $null
    if ($statisticsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $statistics = $statisticsByInterfaceIndex[$interfaceIndex]
    }
    $ipConfiguration = $null
    if ($ipConfigurationsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $ipConfiguration = $ipConfigurationsByInterfaceIndex[$interfaceIndex]
    }
    $addresses = @()
    if ($addressesByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $addresses = @($addressesByInterfaceIndex[$interfaceIndex])
    }
    $routes = @()
    if ($routesByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $routes = @($routesByInterfaceIndex[$interfaceIndex])
    }
    $dns = @()
    if ($dnsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $dns = @($dnsByInterfaceIndex[$interfaceIndex])
    }
    $gateways = @(
        @($ipConfiguration.IPv4DefaultGateway | Where-Object { $null -ne $_.NextHop } | ForEach-Object { [string]$_.NextHop })
        @($ipConfiguration.IPv6DefaultGateway | Where-Object { $null -ne $_.NextHop } | ForEach-Object { [string]$_.NextHop })
    )
    [ordered]@{
        interface_guid = if ($null -eq $adapter.InterfaceGuid) { $null } else { [string]$adapter.InterfaceGuid }
        interface_index = $interfaceIndex
        name = [string]$adapter.Name
        description = if ($null -eq $adapter.InterfaceDescription) { $null } else { [string]$adapter.InterfaceDescription }
        status = if ($null -eq $adapter.Status) { $null } else { [string]$adapter.Status }
        virtual = if ($null -eq $adapter.Virtual) { $null } else { [bool]$adapter.Virtual }
        hardware_interface = if ($null -eq $adapter.HardwareInterface) { $null } else { [bool]$adapter.HardwareInterface }
        manufacturer = if ($null -eq $signedDriver.Manufacturer) { $null } else { [string]$signedDriver.Manufacturer }
        model = if ($null -eq $signedDriver.DeviceName) { $null } else { [string]$signedDriver.DeviceName }
        driver_description = if ($null -eq $adapter.DriverDescription) { $null } else { [string]$adapter.DriverDescription }
        driver_provider = if ($null -eq $signedDriver.DriverProviderName) { $null } else { [string]$signedDriver.DriverProviderName }
        driver_version = if ($null -ne $signedDriver.DriverVersion) {
            [string]$signedDriver.DriverVersion
        } elseif ($null -ne $adapter.DriverVersion) {
            [string]$adapter.DriverVersion
        } else {
            $null
        }
        mac_address = if ($null -eq $adapter.MacAddress) { $null } else { [string]$adapter.MacAddress }
        link_speed = if ($null -eq $adapter.LinkSpeed) { $null } else { [string]$adapter.LinkSpeed }
        statistics_available = $statisticsSourceAvailable -and $null -ne $statistics
        ip_configuration_available = $ipConfigurationSourceAvailable -and $null -ne $ipConfiguration
        addresses_available = $addressesSourceAvailable
        routes_available = $routesSourceAvailable
        dns_available = $dnsSourceAvailable
        received_bytes = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedBytes }
        sent_bytes = if ($null -eq $statistics) { $null } else { [long]$statistics.SentBytes }
        received_packets = if ($null -eq $statistics) { $null } else { [long]($statistics.ReceivedUnicastPackets + $statistics.ReceivedMulticastPackets + $statistics.ReceivedBroadcastPackets) }
        sent_packets = if ($null -eq $statistics) { $null } else { [long]($statistics.SentUnicastPackets + $statistics.SentMulticastPackets + $statistics.SentBroadcastPackets) }
        received_errors = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedPacketErrors }
        sent_errors = if ($null -eq $statistics) { $null } else { [long]$statistics.OutboundPacketErrors }
        received_discards = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedDiscardedPackets }
        sent_discards = if ($null -eq $statistics) { $null } else { [long]$statistics.OutboundDiscardedPackets }
        addresses = $addresses
        routes = $routes
        gateways = $gateways
        dns_servers = @($dns)
    }
})

[ordered]@{
    schema_version = '1.0.0'
    powershell_edition = [string]$PSVersionTable.PSEdition
    powershell_version = [string]$PSVersionTable.PSVersion
    adapters = $adapters
} | ConvertTo-Json -Compress -Depth 8
