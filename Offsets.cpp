#include "Includes.h"

HWND hGameWnd;
HWND hOverlayWnd;
RECT wndRect;

uint64 dwUWorld = 0x0;
uint64 dwLocalplayer;
uint64 dwLocalPawn;
uint64 dwLocalMesh;
uint64 dwULevel;
uint64 dwActorArray;
uint64 dwPlayerController;
uint64 dwPlayerCameraManager;
uint64 dwAnimScript;

uint64  Ulevel = 0xB80;
uint64  actorArray = 0x260;
uint64  actorCount = 0x8;
uint64  ObjectID = 0xC;
uint64  UlocalPlayer = 0x100;
uint64  UWorld = 0x44CF998;
uint64  GInstance = 0x2E0;
uint64  ULevel = 0;
uint64  GameInstance = 0;
uint64  LocalPlayer = 0;
uint64  LocalPlayerx = 0;
uint64  ActorArray = 0;
uint64  PlayerController = 0;
uint64  PlayerCamera = 0;
uint64  PlayerCameraCache = 0;
uint64  RootComponent = 0x1F0; // Actor -> RootComponent
uint64  WeaponEntityComp = 0x3C0; // STExtraWeapon -> WeaponEntityComp
uint64  ComponentVelocity = 0x160; // SceneComponent -> ComponentVelocity
uint64  RelativeLocation = 0x108; // SceneComponent -> RelativeLocation
uint64  Mesh = 0x4C8; // Character -> Mesh
uint64  TeamID = 0x818; // UAECharacter -> TeamID
uint64  PlayerName = 0x808; // UAECharacter -> PlayerName
uint64  bIsAI = 0x800; // UAECharacter -> bIsAI
uint64  PlayerKey = 0x7f0; // UAECharacter -> PlayerKey
uint64  SpectatedCount = 0x1d98; // STExtraBaseCharacter -> SpectatedCount
uint64  bIsWeaponFiring = 0x1b3c; // STExtraBaseCharacter -> bIsWeaponFiring
uint64  bHealth = 0x18e4; // STExtraBaseCharacter -> Health
uint64  HealthStatus = 0x1490; // STExtraBaseCharacter -> HealthStatus 0x1478
uint64  VehicleSeatIdx = 0x1450; // STExtraBaseCharacter -> VehicleSeatIdx
uint64  CurrentVehicle = 0x1448; // STExtraBaseCharacter -> CurrentVehicle
uint64  STCharacterMovement = 0x1138; // STExtraBaseCharacter -> STCharacterMovement
uint64  LocalSimulateStates = 0xee8; // STExtraBaseCharacter -> LocalSimulateStates
uint64  WeaponManagerComponent = 0x888; // STExtraBaseCharacter -> WeaponManagerComponent
uint64  SkydivingComponent = 0x2078; // STExtraPlayerCharacter -> SkydivingComponent
uint64  STPlayerController = 0x1F68; // STExtraPlayerCharacter -> STPlayerController 
uint64  PlayerCameraManager = 0x470; // PlayerController -> PlayerCameraManager
uint64  STExtraBaseCharacter = 0xfb0; // STExtraPlayerController -> STExtraBaseCharacter
uint64  CurrentWeaponReplicated = 0x518; // WeaponManagerComponent -> CurrentWeaponReplicated
uint64  RotationVec = 0x574; // MinimalViewInfo -> Rotation
uint64  LocationVec = 0x568; // MinimalViewInfo -> Location
uint64  FOV = 0x560; // MinimalViewInfo -> FOV
uint64  POV = 0x10; // CameraCacheEntry -> POV
uint64  RecoilMultiplierVertical = 0x2b4; // WeaponAttachmentData -> RecoilMultiplierVertical
uint64  MultipleFiringBulletsSpread = 0x70; // WeaponAttachmentData -> MultipleFiringBulletsSpread
uint64  AnimationKickMultiplier = 0x64; // WeaponAttachmentData -> AnimationKickMultiplier
uint64  SwayMultiplier = 0x60; // WeaponAttachmentData -> SwayMultiplier
uint64  JumpZVelocity = 0x1b4; // CharacterMovementComponent -> JumpZVelocity
uint64  MinWalkSpeedModifier = 0x83c; // STCharacterMovementComponent -> MinWalkSpeedModifier
uint64  WalkSpeedCurveScale = 0x82c; // STCharacterMovementComponent -> WalkSpeedCurveScale
uint64  LastRenderTime = 0x318; // PrimitiveComponent -> LastRenderTime
uint64  VehicleShapeType = 0x419; // STExtraVehicleBase -> VehicleShapeType
uint64  CameraCache = 0xF80; // PlayerCameraManager -> CameraCache
uint64  FreefallVelocitySettings = 0xac8; // TslSkydiveComponent -> FreefallVelocitySettings
uint64  ArrTslWeaponAttachmentData = 0x110; // WeaponEntity -> ArrTslWeaponAttachmentData
uint64  BulletFireSpeed = 0x638; // ShootWeaponEntity -> BulletFireSpeed
uint64  bHasAutoFireMode = 0x414; // ShootWeaponEntity -> bHasAutoFireMode
uint64  offset_boneArray = 0x6F8; //+
uint64  offset_ComponentToWorld = 0x1B0;//+
uint64  offset_LocalPawn = 0x450;
uint64  dwLineOfSightTo = 0x10BE7C0;
uint64  GNames = 0x4680CB0;