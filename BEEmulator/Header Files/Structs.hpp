#pragma once
extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" PVOID FltGetRoutineAddress(PCSTR FltMgrRoutineName);
extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _POOL_TRACKER_BIG_PAGES
{
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern : 8;                                                        //0xc
	ULONG PoolType : 12;                                                      //0xc
	ULONG SlushSize : 12;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
}POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	_In_ PRKAPC Apc,
	_Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_opt_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);

typedef struct
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	VOID* SListFaultAddress;                                                //0x18
	ULONGLONG QuantumTarget;                                                //0x20
	VOID* InitialStack;                                                     //0x28
	VOID* volatile StackLimit;                                              //0x30
	VOID* StackBase;                                                        //0x38
	ULONGLONG ThreadLock;                                                   //0x40
	volatile ULONGLONG CycleTime;                                           //0x48
	ULONG CurrentRunTime;                                                   //0x50
	ULONG ExpectedRunTime;                                                  //0x54
	VOID* KernelStack;                                                      //0x58
	struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
	struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
	char WaitRegister;                                                      //0x70
	volatile UCHAR Running;                                                 //0x71
	UCHAR Alerted[2];                                                       //0x72
	union
	{
		struct
		{
			ULONG AutoBoostActive : 1;                                        //0x74
			ULONG ReadyTransition : 1;                                        //0x74
			ULONG WaitNext : 1;                                               //0x74
			ULONG SystemAffinityActive : 1;                                   //0x74
			ULONG Alertable : 1;                                              //0x74
			ULONG UserStackWalkActive : 1;                                    //0x74
			ULONG ApcInterruptRequest : 1;                                    //0x74
			ULONG QuantumEndMigrate : 1;                                      //0x74
			ULONG UmsDirectedSwitchEnable : 1;                                //0x74
			ULONG TimerActive : 1;                                            //0x74
			ULONG SystemThread : 1;                                           //0x74
			ULONG ProcessDetachActive : 1;                                    //0x74
			ULONG CalloutActive : 1;                                          //0x74
			ULONG ScbReadyQueue : 1;                                          //0x74
			ULONG ApcQueueable : 1;                                           //0x74
			ULONG ReservedStackInUse : 1;                                     //0x74
			ULONG UmsPerformingSyscall : 1;                                   //0x74
			ULONG TimerSuspended : 1;                                         //0x74
			ULONG SuspendedWaitMode : 1;                                      //0x74
			ULONG SuspendSchedulerApcWait : 1;                                //0x74
			ULONG CetShadowStack : 1;                                         //0x74
			ULONG Reserved : 11;                                              //0x74
		};
		LONG MiscFlags;                                                     //0x74
	};
	union
	{
		struct
		{
			ULONG BamQosLevel : 2;                                            //0x78
			ULONG AutoAlignment : 1;                                          //0x78
			ULONG DisableBoost : 1;                                           //0x78
			ULONG AlertedByThreadId : 1;                                      //0x78
			ULONG QuantumDonation : 1;                                        //0x78
			ULONG EnableStackSwap : 1;                                        //0x78
			ULONG GuiThread : 1;                                              //0x78
			ULONG DisableQuantum : 1;                                         //0x78
			ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
			ULONG DeferPreemption : 1;                                        //0x78
			ULONG QueueDeferPreemption : 1;                                   //0x78
			ULONG ForceDeferSchedule : 1;                                     //0x78
			ULONG SharedReadyQueueAffinity : 1;                               //0x78
			ULONG FreezeCount : 1;                                            //0x78
			ULONG TerminationApcRequest : 1;                                  //0x78
			ULONG AutoBoostEntriesExhausted : 1;                              //0x78
			ULONG KernelStackResident : 1;                                    //0x78
			ULONG TerminateRequestReason : 2;                                 //0x78
			ULONG ProcessStackCountDecremented : 1;                           //0x78
			ULONG RestrictedGuiThread : 1;                                    //0x78
			ULONG VpBackingThread : 1;                                        //0x78
			ULONG ThreadFlagsSpare : 1;                                       //0x78
			ULONG EtwStackTraceApcInserted : 8;                               //0x78
		};
		volatile LONG ThreadFlags;                                          //0x78
	};
	volatile UCHAR Tag;                                                     //0x7c
	UCHAR SystemHeteroCpuPolicy;                                            //0x7d
	UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
	UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
	union
	{
		struct
		{
			UCHAR RunningNonRetpolineCode : 1;                                //0x7f
			UCHAR SpecCtrlSpare : 7;                                          //0x7f
		};
		UCHAR SpecCtrl;                                                     //0x7f
	};
	ULONG SystemCallNumber;                                                 //0x80
	ULONG ReadyTime;                                                        //0x84
	VOID* FirstArgument;                                                    //0x88
	struct _KTRAP_FRAME* TrapFrame;                                         //0x90
	union
	{
		struct _KAPC_STATE ApcState;                                        //0x98
		struct
		{
			UCHAR ApcStateFill[43];                                         //0x98
			CHAR Priority;                                                  //0xc3
			ULONG UserIdealProcessor;                                       //0xc4
		};
	};
	volatile LONGLONG WaitStatus;                                           //0xc8
	struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
	union
	{
		struct _LIST_ENTRY WaitListEntry;                                   //0xd8
		struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
	};
	struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
	VOID* Teb;                                                              //0xf0
	ULONGLONG RelativeTimerBias;                                            //0xf8
	struct _KTIMER Timer;                                                   //0x100
	union
	{
		struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
		struct
		{
			UCHAR WaitBlockFill4[20];                                       //0x140
			ULONG ContextSwitches;                                          //0x154
		};
		struct
		{
			UCHAR WaitBlockFill5[68];                                       //0x140
			volatile UCHAR State;                                           //0x184
			CHAR Spare13;                                                   //0x185
			UCHAR WaitIrql;                                                 //0x186
			CHAR WaitMode;                                                  //0x187
		};
		struct
		{
			UCHAR WaitBlockFill6[116];                                      //0x140
			ULONG WaitTime;                                                 //0x1b4
		};
		struct
		{
			UCHAR WaitBlockFill7[164];                                      //0x140
			union
			{
				struct
				{
					SHORT KernelApcDisable;                                 //0x1e4
					SHORT SpecialApcDisable;                                //0x1e6
				};
				ULONG CombinedApcDisable;                                   //0x1e4
			};
		};
		struct
		{
			UCHAR WaitBlockFill8[40];                                       //0x140
			struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
		};
		struct
		{
			UCHAR WaitBlockFill9[88];                                       //0x140
			struct _XSTATE_SAVE* XStateSave;                                //0x198
		};
		struct
		{
			UCHAR WaitBlockFill10[136];                                     //0x140
			VOID* volatile Win32Thread;                                     //0x1c8
		};
		struct
		{
			UCHAR WaitBlockFill11[176];                                     //0x140
			struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
			struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
		};
	};
	VOID* Spare21;                                                          //0x200
	struct _LIST_ENTRY QueueListEntry;                                      //0x208
	union
	{
		volatile ULONG NextProcessor;                                       //0x218
		struct
		{
			ULONG NextProcessorNumber : 31;                                   //0x218
			ULONG SharedReadyQueue : 1;                                       //0x218
		};
	};
	LONG QueuePriority;                                                     //0x21c
	struct _KPROCESS* Process;                                              //0x220
	union
	{
		struct _GROUP_AFFINITY UserAffinity;                                //0x228
		struct
		{
			UCHAR UserAffinityFill[10];                                     //0x228
			CHAR PreviousMode;                                              //0x232
			CHAR BasePriority;                                              //0x233
			union
			{
				CHAR PriorityDecrement;                                     //0x234
				struct
				{
					UCHAR ForegroundBoost : 4;                                //0x234
					UCHAR UnusualBoost : 4;                                   //0x234
				};
			};
			UCHAR Preempted;                                                //0x235
			UCHAR AdjustReason;                                             //0x236
			CHAR AdjustIncrement;                                           //0x237
		};
	};
	ULONGLONG AffinityVersion;                                              //0x238
	union
	{
		struct _GROUP_AFFINITY Affinity;                                    //0x240
		struct
		{
			UCHAR AffinityFill[10];                                         //0x240
			UCHAR ApcStateIndex;                                            //0x24a
			UCHAR WaitBlockCount;                                           //0x24b
			ULONG IdealProcessor;                                           //0x24c
		};
	};
	ULONGLONG NpxState;                                                     //0x250
	union
	{
		struct _KAPC_STATE SavedApcState;                                   //0x258
		struct
		{
			UCHAR SavedApcStateFill[43];                                    //0x258
			UCHAR WaitReason;                                               //0x283
			CHAR SuspendCount;                                              //0x284
			CHAR Saturation;                                                //0x285
			USHORT SListFaultCount;                                         //0x286
		};
	};
	union
	{
		struct _KAPC SchedulerApc;                                          //0x288
		struct
		{
			UCHAR SchedulerApcFill0[1];                                     //0x288
			UCHAR ResourceIndex;                                            //0x289
		};
		struct
		{
			UCHAR SchedulerApcFill1[3];                                     //0x288
			UCHAR QuantumReset;                                             //0x28b
		};
		struct
		{
			UCHAR SchedulerApcFill2[4];                                     //0x288
			ULONG KernelTime;                                               //0x28c
		};
		struct
		{
			UCHAR SchedulerApcFill3[64];                                    //0x288
			struct _KPRCB* volatile WaitPrcb;                               //0x2c8
		};
		struct
		{
			UCHAR SchedulerApcFill4[72];                                    //0x288
			VOID* LegoData;                                                 //0x2d0
		};
		struct
		{
			UCHAR SchedulerApcFill5[83];                                    //0x288
			UCHAR CallbackNestingLevel;                                     //0x2db
			ULONG UserTime;                                                 //0x2dc
		};
	};
	struct _KEVENT SuspendEvent;                                            //0x2e0
	struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
	struct _LIST_ENTRY MutantListHead;                                      //0x308
	UCHAR AbEntrySummary;                                                   //0x318
	UCHAR AbWaitEntryCount;                                                 //0x319
	UCHAR AbAllocationRegionCount;                                          //0x31a
	CHAR SystemPriority;                                                    //0x31b
	ULONG SecureThreadCookie;                                               //0x31c
	char LockEntries[0x240];                                                //0x320
	struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x560
	struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x568
	UCHAR PriorityFloorCounts[16];                                          //0x570
	ULONG PriorityFloorSummary;                                             //0x580
	volatile LONG AbCompletedIoBoostCount;                                  //0x584
	volatile LONG AbCompletedIoQoSBoostCount;                               //0x588
	volatile SHORT KeReferenceCount;                                        //0x58c
	UCHAR AbOrphanedEntrySummary;                                           //0x58e
	UCHAR AbOwnedEntryCount;                                                //0x58f
	ULONG ForegroundLossTime;                                               //0x590
	union
	{
		struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x598
		struct
		{
			struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x598
			ULONGLONG InGlobalForegroundList;                               //0x5a0
		};
	};
	LONGLONG ReadOperationCount;                                            //0x5a8
	LONGLONG WriteOperationCount;                                           //0x5b0
	LONGLONG OtherOperationCount;                                           //0x5b8
	LONGLONG ReadTransferCount;                                             //0x5c0
	LONGLONG WriteTransferCount;                                            //0x5c8
	LONGLONG OtherTransferCount;                                            //0x5d0
	struct _KSCB* QueuedScb;                                                //0x5d8
	volatile ULONG ThreadTimerDelay;                                        //0x5e0
	union
	{
		volatile LONG ThreadFlags2;                                         //0x5e4
		struct
		{
			ULONG PpmPolicy : 2;                                              //0x5e4
			ULONG ThreadFlags2Reserved : 30;                                  //0x5e4
		};
	};
	VOID* SchedulerAssist;                                                  //0x5e8
} KThread;

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);