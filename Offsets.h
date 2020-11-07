#pragma once

enum EBoneIndex : int32
{
	Root = 0,
	pelvis = 1,
	spine_01 = 2,
	spine_02 = 3,
	spine_03 = 4,
	neck_01 = 5,
	Head = 6,
	hair_01 = 7,
	hair_02 = 8,
	hair_03 = 9,
	hair_04 = 10,
	R_eye = 11,
	L_eye = 12,
	camera_fpp = 13,
	clavicle_r = 14,
	upperarm_r = 15,
	lowerarm_r = 16,
	lowerarm_twist_01_r = 17,
	hand_r = 18,
	middle_01_r = 19,
	middle_02_r = 20,
	middle_03_r = 21,
	ring_01_r = 22,
	ring_02_r = 23,
	ring_03_r = 24,
	pinky_01_r = 25,
	pinky_02_r = 26,
	pinky_03_r = 27,
	index_01_r = 28,
	index_02_r = 29,
	index_03_r = 30,
	thumb_01_r = 31,
	thumb_02_r = 32,
	thumb_03_r = 33,
	item_r = 34,
	clavicle_l = 35,
	upperarm_l = 36,
	lowerarm_l = 37,
	lowerarm_twist_01_l = 38,
	hand_l = 39,
	thumb_01_l = 40,
	thumb_02_l = 41,
	thumb_03_l = 42,
	index_01_l = 43,
	index_02_l = 44,
	index_03_l = 45,
	middle_01_l = 46,
	middle_02_l = 47,
	middle_03_l = 48,
	ring_01_l = 49,
	ring_02_l = 50,
	ring_03_l = 51,
	pinky_01_l = 52,
	pinky_02_l = 53,
	pinky_03_l = 54,
	item_l = 55,
	thigh_r = 56,
	calf_r = 57,
	foot_r = 58,
	ball_r = 59,
	thigh_l = 60,
	calf_l = 61,
	foot_l = 62,
	ball_l = 63,
	ik_hand_root = 64,
	ik_hand_gun = 65,
	ik_hand_l = 66,
	ik_hand_r = 67,
	camera_tpp = 68,
	VB_Dummy = 69,
};

extern HWND hGameWnd;
extern HWND hOverlayWnd;
extern RECT wndRect;

extern uint64 dwUWorld;
extern uint64 dwLocalplayer;
extern uint64 dwLocalPawn;
extern uint64 dwLocalMesh;
extern uint64 dwULevel;
extern uint64 dwActorArray;
extern uint64 dwPlayerController;
extern uint64 dwPlayerCameraManager;
extern uint64 dwAnimScript;
extern uint64 Ulevel ;
extern uint64 actorArray ;
extern uint64 actorCount ;
extern uint64 ObjectID ;
extern uint64 UlocalPlayer ;
extern uint64 UWorld ;
extern uint64 GInstance ;
extern uint64 ULevel ;//;
extern uint64 GameInstance ;//;
extern uint64 LocalPlayer ;//;
extern uint64 LocalPlayerx ;//;
extern uint64 ActorArray ;//;
extern uint64 PlayerController ;//;
extern uint64 PlayerCamera ;//;
extern uint64 PlayerCameraCache ;//;
extern uint64 RootComponent ;//x1F0; // Actor -> RootComponent
extern uint64 WeaponEntityComp ;//x3c0; // STExtraWeapon -> WeaponEntityComp
extern uint64 ComponentVelocity ;//x160; // SceneComponent -> ComponentVelocity
extern uint64 RelativeLocation ;//x108; // SceneComponent -> RelativeLocation
extern uint64 Mesh ;//x4C8; // Character -> Mesh
extern uint64 TeamID ;//x818; // UAECharacter -> TeamID
extern uint64 PlayerName ;//x808; // UAECharacter -> PlayerName
extern uint64 bIsAI ;//x800; // UAECharacter -> bIsAI
extern uint64 PlayerKey ;//x7f0; // UAECharacter -> PlayerKey
extern uint64 SpectatedCount ;//x1d98; // STExtraBaseCharacter -> SpectatedCount
extern uint64 bIsWeaponFiring ;//x1b3c; // STExtraBaseCharacter -> bIsWeaponFiring
extern uint64 bHealth;//x18e4; // STExtraBaseCharacter -> Health
extern uint64 HealthStatus ;//x1490; // STExtraBaseCharacter -> HealthStatus 0x1478
extern uint64 VehicleSeatIdx ;//x1450; // STExtraBaseCharacter -> VehicleSeatIdx
extern uint64 CurrentVehicle ;//x1448; // STExtraBaseCharacter -> CurrentVehicle
extern uint64 STCharacterMovement ;//x1138; // STExtraBaseCharacter -> STCharacterMovement
extern uint64 LocalSimulateStates ;//xee8; // STExtraBaseCharacter -> LocalSimulateStates
extern uint64 WeaponManagerComponent ;//x888; // STExtraBaseCharacter -> WeaponManagerComponent
extern uint64 SkydivingComponent ;//x2078; // STExtraPlayerCharacter -> SkydivingComponent
extern uint64 STPlayerController ;//x1F68; // STExtraPlayerCharacter -> STPlayerController 
extern uint64 PlayerCameraManager ;//x470; // PlayerController -> PlayerCameraManager
extern uint64 STExtraBaseCharacter ;//xfb0; // STExtraPlayerController -> STExtraBaseCharacter
extern uint64 CurrentWeaponReplicated ;//x518; // WeaponManagerComponent -> CurrentWeaponReplicated
extern uint64 RotationVec ;//x574; // MinimalViewInfo -> Rotation
extern uint64 LocationVec ;//x568; // MinimalViewInfo -> Location
extern uint64 FOV ;//x560; // MinimalViewInfo -> FOV
extern uint64 POV ;//x10; // CameraCacheEntry -> POV
extern uint64 RecoilMultiplierVertical ;//x2b4; // WeaponAttachmentData -> RecoilMultiplierVertical
extern uint64 MultipleFiringBulletsSpread ;//x70; // WeaponAttachmentData -> MultipleFiringBulletsSpread
extern uint64 AnimationKickMultiplier ;//x64; // WeaponAttachmentData -> AnimationKickMultiplier
extern uint64 SwayMultiplier ;//x60; // WeaponAttachmentData -> SwayMultiplier
extern uint64 JumpZVelocity ;//x1b4; // CharacterMovementComponent -> JumpZVelocity
extern uint64 MinWalkSpeedModifier ;//x83c; // STCharacterMovementComponent -> MinWalkSpeedModifier
extern uint64 WalkSpeedCurveScale ;//x82c; // STCharacterMovementComponent -> WalkSpeedCurveScale
extern uint64 LastRenderTime ;//x318; // PrimitiveComponent -> LastRenderTime
extern uint64 VehicleShapeType ;//x419; // STExtraVehicleBase -> VehicleShapeType
extern uint64 CameraCache ;//xF80; // PlayerCameraManager -> CameraCache
extern uint64 FreefallVelocitySettings ;//xac8; // TslSkydiveComponent -> FreefallVelocitySettings
extern uint64 ArrTslWeaponAttachmentData ;//x110; // WeaponEntity -> ArrTslWeaponAttachmentData
extern uint64 BulletFireSpeed ;//x638; // ShootWeaponEntity -> BulletFireSpeed
extern uint64 bHasAutoFireMode ;//x414; // ShootWeaponEntity -> bHasAutoFireMode
extern uint64 offset_boneArray ;//x6F8; //+
extern uint64 offset_ComponentToWorld ;//x1B0;//+
extern uint64 offset_LocalPawn ;//x450;
extern uint64 dwLineOfSightTo ;//x10BE7C0;
extern uint64 GNames ;//x4680CB0;
//#pragma once
//#define Offset_UWorld 0x44CF998 //48 89 05 ? ? ? ? 48 83 C4 28 C3 B8 ? ? ? ? 48 C7 44 24 ? ? ? ? ? 66 C1 C8 08
//#define UWorld_GetCurrentLevel 0xA90
//#define UWorld_GetGameInstance 0x2E0
//#define UGameInstance_GetLocalPlayer 0x100
//#define ULevel_GetActors 0x260
//#define ULocalPlayer_GetPlayerController 0x30
//
//#define offs_uworld 0x44CF998 //48 89 05 ? ? ? ? 48 83 C4 28 C3 B8 ? ? ? ? 48 C7 44 24 ? ? ? ? ? 66 C1 C8 08
//#define offs_localplayer 0x728C0D0 //48 89 3d ? ? ? ? f2 0f 10 05 ? ? ? ?
//#define offs_gnames 0x726FA38 
//#define offs_decrypt 0x4EDEA28
//#define offs_chunk 0x3FC0 //c1 ? ? 8b ? c1 ? 1f 03 ? 69 ? ? ? ? ? 44 2b f8
//
//#define offs_PersistentLevel          0x40 //E8 ? ? ? ? 39 5C 24 48 
//#define offs_ActorsArray              0x98 //E8 ? ? ? ? 39 5C 24 48 7E 29
//#define offs_PlayerControllers        0x38
//#define Offs_LocalPawn				  0x480 //8B 90 ? ? ? ? C1 EA 04 41 84 D4
//#define offs_PlayerCameraManager      0x4A0 //41 ff 90 ? ? ? ? ? 8b ? ? ? ? ? 48 85 c9 74 ? 48 8b 01 4c 8d
//#define offs_Actor_ObjID			  0x8
//#define offs_Actor_Health			  0xC6C //0F 57 C0 0F 2F 81 ? ? ? ? 72 0C
//#define offs_Actor_RootComponent	  0x298 //E8 ? ? ? ? B0 01 48 8B 4D 00 
//#define offs_Actor_TeamNumber		  0xFB8
//#define offs_Mesh					  0x4C0 //48 8B 99 ? ? ? ? 48 ? ? 48 ? ? 0F 84 ? ? ? ? 0F 10
//#define offs_Mesh_BoneArray		      0xAD0 //F3 0F 10 81 ?? ?? ?? ?? F3 0F 10 0D ?? ?? ?? ?? 0F 2F C1
//#define offs_Mesh_ComponentToWorld    0x340 //0F 8D ? ? ? ? 0F 10 9F ? ? ? ?
//#define offs_relativepos			  0x364
//#define offs_absolutepos			  0x350 //48 85 C0 74 23 0F 10 88 ?? ?? 00 00 0F 28 C1
//#define offs_CameraRotation		      0xA10 //f2 0f 10 81 ? ? ? ? f2 41 0f 11 ? 8b 81 ? ? ? ? 41 89 ? ? c3
//#define offs_CameraLocation		      0xF94 //E8 ? ? ? ? 44 8B 8F ? ? ? ? 0F 28 D6
//#define offs_CameraFov			      0xA04 //77 08 F3 0F 10 81 ? ? ? ? C3 CC CC CC CC CC CC CC 48 89 5C 24 ?
//#define offs_UANIMINSTANCE			  0xC78
//#define offs_CONTROL_ROTATION_CP      0x6A8
//#define offs_RECOIL_ADS_ROTATION_CP   0xB48
//#define offs_LastRenderTimeOnScreen   0x778 //0F 2F 83 ? ? ? ? 0F 42 C8
//
////items
//#define offs_DroppedItem              0x1F0
//#define offs_DroppedItemGroup_Count offs_DroppedItem + 0x8
//#define offs_DroppedItemGroup_UItem   0x660 //0F B6 F8 48 85 D2 74 13 4C 8B CE 4C 8B C5 49 8B CE ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?
//#define offs_UITEM_ID				  0x270
//#define offs_ITEM_PACKAGE             0x520 //48 8B 8F ? ? ? ? 48 63 D3 48 8B 14 D1 48
//
////prediction
//#define offs_WEAPONPROCESSOR 0x1630
//#define offs_EquippedWeapons 0x2B8
//#define offs_WEAPONTRAJECTORYDATA 0xED0
//#define offs_TRAJECTORYCONFIG 0xB8
//#define offs_COMPONENT_VELOCITY 0x308

