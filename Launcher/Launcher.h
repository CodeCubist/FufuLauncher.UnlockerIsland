#pragma once
#include <windows.h>

#ifdef LAUNCHER_EXPORTS
#define LAUNCHER_API __declspec(dllexport)
#else
#endif

#pragma pack(push, 1)

struct IslandFunctionOffsets
{
    DWORD GameManagerAwake;
    DWORD MickeyWonderMethod;
    DWORD MickeyWonderMethodPartner;
    DWORD MickeyWonderMethodPartner2;
    DWORD SetLastUid;
    DWORD SetFieldOfView;
    DWORD SetEnableFogRendering;
    DWORD GetTargetFrameRate;
    DWORD SetTargetFrameRate;
    DWORD OpenTeam;
    DWORD OpenTeamPageAccordingly;
    DWORD CheckCanEnter;
    DWORD SetupQuestBanner;
    DWORD FindGameObject;
    DWORD SetActive;
    DWORD EventCameraMove;
    DWORD ShowOneDamageTextEx;
    DWORD SwitchInputDeviceToTouchScreen;
    DWORD MickeyWonderCombineEntryMethod;
    DWORD MickeyWonderCombineEntryMethodPartner;
    DWORD SetupResinList;
    DWORD ResinList;
    DWORD ResinListGetCount;
    DWORD ResinListGetItem;
    DWORD ResinListRemove;
};

struct IslandEnvironment
{
    DWORD Size;
    DWORD State;
    DWORD LastError;
    DWORD Uid;
    IslandFunctionOffsets IslandFunctionOffsets;
    BOOL  EnableSetFieldOfView;
    FLOAT FieldOfView;
    BOOL  FixLowFovScene;
    BOOL  DisableFog;
    BOOL  EnableSetTargetFrameRate;
    DWORD TargetFrameRate;
    BOOL  RemoveOpenTeamProgress;
    BOOL  HideQuestBanner;
    BOOL  DisableEventCameraMove;
    BOOL  DisableShowDamageText;
    BOOL  UsingTouchScreen;
    BOOL  RedirectCombineEntry;
    BOOL  ResinListItemId000106Allowed;
    BOOL  ResinListItemId000201Allowed;
    BOOL  ResinListItemId107009Allowed;
    BOOL  ResinListItemId107012Allowed;
    BOOL  ResinListItemId220007Allowed;
};

#pragma pack(pop)

extern "C" {
    LAUNCHER_API int LaunchGameAndInject(const wchar_t* gamePath, const wchar_t* dllPath, const wchar_t* commandLineArgs, wchar_t* errorMessage, int errorMessageSize);
    LAUNCHER_API int GetDefaultDllPath(wchar_t* dllPath, int dllPathSize);
    LAUNCHER_API bool ValidateGamePath(const wchar_t* gamePath);
    LAUNCHER_API bool ValidateDllPath(const wchar_t* dllPath);

    LAUNCHER_API void UpdateConfig(
        const wchar_t* gamePath, 
        int hideQuest,          
        int disableDamage,      
        int useTouch,           
        int disableEventCam,    
        int removeTeamProgress, 
        int redirectCombine,    
        int resin1,             
        int resin2,             
        int resin3,             
        int resin4,             
        int resin5              
    );
}