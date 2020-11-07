#include	"Includes.h"


/*
-=-=-=
Colors
-=-=-=
*/
//Color 		CMath::colorBlack			=	Color ( 0,		0,			0,		255	);
//Color 		CMath::colorRed				=	Color ( 200,	0,			0,		255	);
//Color 		CMath::colorGreen			=	Color ( 0,		255,		0,		255	);
//Color 		CMath::colorBlue			=	Color ( 0,		0,			255,	255	);
//Color 		CMath::colorYellow			=	Color ( 255,	255,		0,		255	);
//Color 		CMath::colorOrange			=	Color ( 230,	165,		0,		255	);
//Color 		CMath::colorMagenta			=	Color ( 255,	0,			255,	255	);
//Color 		CMath::colorCyan			=	Color ( 0,		255,		255,	255	);
//Color 		CMath::colorWhite			=	Color ( 255,	255,		255,	255	);
//Color 		CMath::colorLtGrey			=	Color ( 191,	191,		191,	255	);
//Color 		CMath::colorMdGrey			=	Color ( 127,	127,		127,	255	);
//Color 		CMath::colorDkGrey			=	Color ( 63,		63,			63,		255	);
//Color 		CMath::colorMenuHover		=	Color ( 255,	255,		255,	76	);
//Color 		CMath::colorMenuBackground	=	Color ( 20,		20,			20,		155	);//Color ( 0,		0,			0,		76	);
//Color 		CMath::colorAdvert			=	Color ( 255,	255,		0,		127	);
//
///*Color 		CMath::colorBlack_			=	Color ( 0,		0,			0,		155	);
//Color 		CMath::colorRed_			=	Color ( 255,	0,			0,		155	);
//Color 		CMath::colorGreen_			=	Color ( 0,		255,		0,		155	);
//Color 		CMath::colorBlue_			=	Color ( 0,		0,			255,	155	);
//Color 		CMath::colorYellow_			=	Color ( 255,	255,		0,		155	);
//Color 		CMath::colorOrange_			=	Color ( 255,	127,		0,		155	);
//Color 		CMath::colorMagenta_		=	Color ( 255,	0,			255,	155	);
//Color 		CMath::colorCyan_			=	Color ( 0,		255,		255,	155	);
//Color 		CMath::colorWhite_			=	Color ( 255,	255,		255,	155	);
//Color 		CMath::colorLtGrey_			=	Color ( 191,	191,		191,	155	);
//Color 		CMath::colorMdGrey_			=	Color ( 127,	127,		127,	155	);
//Color 		CMath::colorDkGrey_			=	Color ( 63,		63,			63,		155	);*/
//Color 		CMath::colorBlack_			=	Color ( 0,		0,			0,		255	);
//Color 		CMath::colorRed_			=	Color ( 200,	0,			0,		150	);
//Color 		CMath::colorGreen_			=	Color ( 0,		255,		0,		255	);
//Color 		CMath::colorBlue_			=	Color ( 0,		0,			255,	150	);
//Color 		CMath::colorYellow_			=	Color ( 200,	255,		0,		255	);
//Color 		CMath::colorOrange_			=	Color ( 200,	127,		0,		255	);
//Color 		CMath::colorMagenta_		=	Color ( 200,	0,			255,	255	);
//Color 		CMath::colorCyan_			=	Color ( 0,		255,		255,	255	);
//Color 		CMath::colorWhite_			=	Color ( 255,	255,		255,	150	);
//Color 		CMath::colorLtGrey_			=	Color ( 191,	191,		191,	255	);
//Color 		CMath::colorMdGrey_			=	Color ( 127,	127,		127,	255	);
//Color 		CMath::colorDkGrey_			=	Color ( 63,		63,			63,		255	);
FVector FVec;
Color::Color ()
{
	this->R = 0.0f;
	this->G = 0.0f;
	this->B = 0.0f;
	this->A = 0.0f;
}

Color::Color ( int _R, int _G, int _B, int _A )
{
	this->R = ( _R / 255.0f );
	this->G = ( _G / 255.0f );
	this->B = ( _B / 255.0f );
	this->A = ( _A / 255.0f );
}

Color::Color ( float _R, float _G, float _B  )
{
	this->R = _R;
	this->G = _G;
	this->B = _B;
	this->A = 1.0f;
}

float Color::GetRed ()
{
	return this->R;
}

float Color::GetGreen ()
{
	return this->G;
}

float Color::GetBlue ()
{
	return this->B;
}

float Color::GetAlpha ()
{
	return this->A;
}

void Color::SetRed ( float _R )
{
	this->R = _R;
}

void Color::SetGreen ( float _G )
{
	this->G = _G;
}

void Color::SetBlue ( float _B )
{
	this->B = _B;
}

void Color::SetAlpha ( float _A )
{
	this->A = _A;
}

void Color::SetRed ( int _R )
{
	this->R = ( _R / 255.0f );
}

void Color::SetGreen ( int _G )
{
	this->G = ( _G / 255.0f );
}

void Color::SetBlue ( int _B )
{
	this->B = ( _B / 255.0f );
}

void Color::SetAlpha ( int _A )
{
	this->A = ( _A / 255.0f );
}

FRotator::FRotator ()
{
	this->Pitch = 0.0f;
	this->Yaw	= 0.0f;
	this->Roll	= 0.0f;
}

FRotator::FRotator ( float _Pitch, float _Yaw, float _Roll )
{
	this->Pitch = _Pitch;
	this->Yaw 	= _Yaw;
	this->Roll 	= _Roll;
}

float FRotator::GetPitch ()
{
	return this->Pitch;
}

float FRotator::GetYaw ()
{
	return this->Yaw;
}

float FRotator::GetRoll ()
{
	return this->Roll;
}

void FRotator::Normalize ()
{
	while ( this->Yaw > 180.0f )
		this->Yaw -= 360.0f;

	while ( this->Yaw < -180.0f )
		this->Yaw += 360.0f;

	while ( this->Pitch > 180.0f )
		this->Pitch -= 360.0f;

	while ( this->Pitch < -180.0f )
		this->Pitch += 360.0f;
}

FRotator FRotator::operator+ ( const FRotator &A )
{
	return FRotator( this->Pitch + A.Pitch, this->Yaw + A.Yaw, this->Roll + A.Roll );
}

FRotator FRotator::operator- ( const FRotator &A )
{
	return FRotator( this->Pitch - A.Pitch, this->Yaw - A.Yaw, this->Roll - A.Roll );
}

FVector FRotator::ToVector ()
{
	float angle, sr, sp, sy, cr, cp, cy;

	angle = this->Yaw * ( M_PI * 2 / 360 );
	sy = sin( angle );
	cy = cos( angle );

	angle = this->Pitch * ( M_PI * 2 / 360 );
	sp = sin( angle );
	cp = cos( angle );

	angle = this->Roll * ( M_PI * 2 / 360 );
	sr = sin( angle );
	cr = cos( angle );

	return FVector( cp * cy, cp * sy, -sp );
}

void FRotator::GetVectors ( FVector* Forward, FVector* Right, FVector* Up )
{
	static float sr, sp, sy, cr, cp , cy;
	float angle;

	angle = ( float )this->Pitch * ( ( float )M_PI * 2 / 360 );
	sp = sin( angle );
	cp = cos( angle );


	angle = ( float )this->Yaw * ( ( float )M_PI * 2 / 360 );
	sy = sin( angle );
	cy = cos( angle );

	angle = ( float )this->Roll * ( ( float )M_PI * 2 / 360 );
	sr = sin( angle );
	cr = cos( angle );

	if ( Forward )
		*Forward	= FVector( cp * cy, cp * sy, -sp );

	if ( Right )
		*Right		= FVector( -1 * sr * sp * cy +- 1 * cr * -sy, -1 * sr * sp * sy +- 1 * cr * cy, -1 * sr * cp );

	if ( Up )
		*Up			= FVector( cr * sp * cy +- sr * -sy, cr * sp * sy +- sr * cy, cr * cp );
};

FVector::FVector ()
{
	this->X = 0.0f;
	this->Y = 0.0f;
	this->Z = 0.0f;
}

FVector::FVector ( float _X, float _Y, float _Z )
{
	this->X = _X;
	this->Y = _Y;
	this->Z = _Z;
}

FVector FVector::operator+ ( const FVector &A )
{
	return FVector( this->X + A.X, this->Y + A.Y, this->Z + A.Z );
}

FVector FVector::operator+ ( const float A )
{
	return FVector( this->X + A, this->Y + A, this->Z + A );
}

FVector FVector::operator+= ( const FVector &A )
{
	this->X += A.X;
	this->Y += A.Y;
	this->Z += A.Z;
	return *this;
}

FVector FVector::operator+= ( const float A )
{
	this->X += A;
	this->Y += A;
	this->Z += A;
	return *this;
}

FVector FVector::operator- ( const FVector &A )
{
	return FVector( this->X - A.X, this->Y - A.Y, this->Z - A.Z );
}

FVector FVector::operator- ( const float A )
{
	return FVector( this->X - A, this->Y - A, this->Z - A );
}

FVector FVector::operator-= ( const FVector &A )
{
	this->X -= A.X;
	this->Y -= A.Y;
	this->Z -= A.Z;
	return *this;
}

FVector FVector::operator-= ( const float A )
{
	this->X -= A;
	this->Y -= A;
	this->Z -= A;
	return *this;
}

FVector FVector::operator* ( const FVector &A )
{
	return FVector( this->X * A.X, this->Y * A.Y, this->Z * A.Z );
}

FVector FVector::operator* ( const float A )
{
	return FVector( this->X * A, this->Y * A, this->Z * A );
}

FVector FVector::operator*= ( const FVector &A )
{
	this->X *= A.X;
	this->Y *= A.Y;
	this->Z *= A.Z;
	return *this;
}

FVector FVector::operator*= ( const float A )
{
	this->X *= A;
	this->Y *= A;
	this->Z *= A;
	return *this;
}

FVector FVector::operator/ ( const FVector &A )
{
	return FVector( this->X / A.X, this->Y / A.Y, this->Z / A.Z );
}

FVector FVector::operator/ ( const float A )
{
	return FVector( this->X / A, this->Y / A, this->Z / A );
}

FVector FVector::operator/= ( const FVector &A )
{
	this->X /= A.X;
	this->Y /= A.Y;
	this->Z /= A.Z;
	return *this;
}

FVector FVector::operator/= ( const float A )
{
	this->X /= A;
	this->Y /= A;
	this->Z /= A;
	return *this;
}

bool FVector::operator== ( const FVector &A )
{
	if ( this->X == A.X 
		&& this->Y == A.Y
		&& this->Z == A.Z )
		return true;

	return false;
}

bool FVector::operator!= ( const FVector &A )
{
	if ( this->X != A.X 
		|| this->Y != A.Y
		|| this->Z != A.Z )
		return true;

	return false;
}

float FVector::GetX ()
{
	return this->X;
}

float FVector::GetY ()
{
	return this->Y;
}

float FVector::GetZ ()
{
	return this->Z;
}

float FVector::Size ()
{
	return sqrt( ( this->X * this->X ) + ( this->Y * this->Y ) + ( this->Z * this->Z ) );
}
FRotator FRotator::CalcAngle(FVector LocalHeadPosition, FVector AimPosition)
{
	FVector vecDelta = FVector((LocalHeadPosition.X - AimPosition.X), (LocalHeadPosition.Y - AimPosition.Y), (LocalHeadPosition.Z - AimPosition.Z));
	float hyp = (float)sqrt(vecDelta.X * vecDelta.X + vecDelta.Y * vecDelta.Y);

	FRotator ViewAngles = FRotator();
	ViewAngles.Pitch = -(float)atan(vecDelta.Z / hyp) * (float)(180.0f / M_PI);
	ViewAngles.Yaw = (float)atan(vecDelta.Y / vecDelta.X) * (float)(180.0f / M_PI);
	ViewAngles.Roll = (float)0;

	if (vecDelta.X >= 0.0f)
		ViewAngles.Yaw += 180.0f;

	return ViewAngles;
}
FRotator FVector::ToRotator ()
{
	float Yaw;
	float Pitch;
	float Forward;

	if ( this->X == 0.0f
		&& this->Y == 0.0f )
	{
		Yaw = 0.0f;

		if ( this->Z > 0.0f )
			Pitch = 90.0f;

		else
			Pitch = 270.0f;
	}
	else 
	{
		if ( this->X )
			Yaw = ( atan2( this->Y, this->X ) * ( 180.0f / M_PI ) );

		else if ( this->Y > 0 )
			Yaw = 90.0f;

		else 
			Yaw = 270.0f;

		if ( Yaw < 0.0f )
			Yaw += 360.0f;

		Forward = sqrt( ( this->X * this->X ) + ( this->Y * this->Y ) );
		Pitch = ( atan2( this->Z, Forward  ) * ( 180.0f / M_PI ) );

		if ( Pitch < 0.0f )
			Pitch += 360.0f;
	}

	return FRotator( -Pitch, Yaw, 0 );
}

bool FVector::IsValid ()
{
	return *this != FVector( 0, 0, 0 );
}

FVector2D::FVector2D ()
{
	this->X = 0.0f;
	this->Y = 0.0f;
}

FVector2D::FVector2D ( float _X, float _Y )
{
	this->X = _X;
	this->Y = _Y;
}

float FVector2D::GetX ()
{
	return this->X;
}

float FVector2D::GetY ()
{
	return this->Y;
}

float FVector2D::Size ()
{
	return sqrt( ( this->X * this->X ) + ( this->Y * this->Y ) );
}

Matrix::Matrix ()
{
	Forward = Right = Up = FVector( 0, 0, 0 );
}

Matrix::Matrix ( FVector _Forward, FVector _Right, FVector _Up )
{
	Forward = _Forward;
	Right = _Right;
	Up = _Up;
}

//float CMath::GetDistance( centity_t *pEntity, FVector Location )
//{
//	return ( ( pEntity->lerpOrigin - Location ).Size( ) / 36 );
//}

/*
-=-=-=-=-=-=-=-=
3D to 2D Convert
-=-=-=-=-=-=-=-=
*/
float FVector::Dot( FVector pStart, FVector pEnd )
{
	return ( pStart.X * pEnd.X ) + ( pStart.Y * pEnd.Y ) + ( pStart.Z * pEnd.Z );
}
float FVector::Distance(FVector v)
{
	return float(sqrtf(powf(v.X - X, 2.0) + powf(v.Y - Y, 2.0) + powf(v.Z - Z, 2.0)));
}
bool FVector::InAngle( FVector pStart, FVector pEnd, FVector pRotation, int nAngle )
{
	return ( Dot( ( pStart - pEnd ) / ( pStart - pEnd ).Size(), pRotation ) > cos( nAngle * M_PI / 360 ) );
}

int FVector::round( float fValue )
{
	return int( fValue + 0.5f );
}

/*
-=-=-=-=-=-=-=-=
Vector to Origin
-=-=-=-=-=-=-=-=
*/
FVector2D FVector::GetAngleToOrigin(FRotator ViewAngles, FVector vec_Start, FVector vec_End )
{
	FRotator rot_Angle = ( vec_End - vec_Start ).ToRotator( );

	if( rot_Angle.Yaw > 180.0f ) { rot_Angle.Yaw -= 360.0f; }
	else if( rot_Angle.Yaw < -180.0f ) { rot_Angle.Yaw += 360.0f; }

	if( rot_Angle.Pitch > 180.0f ) { rot_Angle.Pitch -= 360.0f; }
	else if( rot_Angle.Pitch < -180.0f ) { rot_Angle.Pitch += 360.0f; }

	rot_Angle.Yaw -= ViewAngles.Yaw;
	rot_Angle.Pitch -= ViewAngles.Pitch;

	if( rot_Angle.Yaw > 180.0f ) { rot_Angle.Yaw -= 360.0f; }
	else if( rot_Angle.Yaw < -180.0f ) { rot_Angle.Yaw += 360.0f; }

	if( rot_Angle.Pitch > 180.0f ) { rot_Angle.Pitch -= 360.0f; }
	else if( rot_Angle.Pitch < -180.0f ) { rot_Angle.Pitch += 360.0f; }

	return FVector2D( rot_Angle.Yaw, rot_Angle.Pitch );
}