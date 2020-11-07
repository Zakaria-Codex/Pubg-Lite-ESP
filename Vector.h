#ifndef	Q_MATH_H
#define	Q_MATH_H

//Globals
#define M_PI 3.14159265358979323846f
#define ANG_CLIP( ang )		if( ang > 180.0f ) { ang -= 360.0f; } else if( ang <- 180.0f ) { ang += 360.0f; }
#define	GENTITYNUM_BITS		10
#define	MAX_GENTITIES		( 1 << GENTITYNUM_BITS )

struct Color;
struct FVector2D;
struct FVector;
struct Matrix;
struct FRotator;

struct Color
{
	float R;
	float G;
	float B;
	float A;

	Color ();
	Color ( int _R, int _G, int _B, int _A );
	Color ( float _R, float _G, float _B  );

	float GetRed ();
	float GetGreen ();
	float GetBlue ();
	float GetAlpha ();

	void SetRed ( float _R );
	void SetGreen ( float _G );
	void SetBlue ( float _B );
	void SetAlpha ( float _A );

	void SetRed ( int _R );
	void SetGreen ( int _G );
	void SetBlue ( int _B );
	void SetAlpha ( int _A );
};


struct FRotator
{
	float Pitch;
	float Yaw;
	float Roll;

	FRotator ();
	FRotator ( float _Pitch, float _Yaw, float _Roll );

	float GetPitch ();
	float GetYaw ();
	float GetRoll ();

	void Normalize ();
	//FRotator FRotator::Normalize180 ();

	FRotator operator+ ( const FRotator &A );
	FRotator operator- ( const FRotator &A );

	void GetVectors ( FVector* Forward, FVector* Right, FVector* Up );

	FVector ToVector ();

	/*char* ToString ()
	{
		static char buffer[ 256 ];
		ZeroMemory( buffer, 256 );

		sprintf( buffer, "rotator( %.2f, %.2f, %.2f )", this->Pitch, this->Yaw, this->Roll );
		return buffer;
	};*/
	FRotator ClampAngles();
	FRotator CalcAngle(FVector LocalHeadPosition, FVector AimPosition);
};

struct FVector2D
{
	float X;
	float Y;

	FVector2D ();
	FVector2D ( float _X, float _Y );

	float GetX ();
	float GetY ();

	float Size ();
};


struct FVector
{
	float X;
	float Y;
	float Z;

	FVector ();
	FVector ( float _X, float _Y, float _Z );

	FVector operator+ ( const FVector &A );
	FVector operator+ ( const float A );
	FVector operator+= ( const FVector &A );
	FVector operator+= ( const float A );
	FVector operator- ( const FVector &A );
	FVector operator- ( const float A );
	FVector operator-= ( const FVector &A );
	FVector operator-= ( const float A );
	FVector operator* ( const FVector &A );
	FVector operator* ( const float A );
	FVector operator*= ( const FVector &A );
	FVector operator*= ( const float A );
	FVector operator/ ( const FVector &A );
	FVector operator/ ( const float A );
	FVector operator/= ( const FVector &A );
	FVector operator/= ( const float A );

	bool operator== ( const FVector &A );
	bool operator!= ( const FVector &A );

	float GetX ();
	float GetY ();
	float GetZ ();

	float Size ();
	//float Dot (const FVector V1,const FVector V2);
	FRotator ToRotator ();

	/*char* toString ()
	{
		static char buffer[ 256 ];
		ZeroMemory( buffer, 256 );

		sprintf( buffer, "vector( %.2f, %.2f, %.2f )", this->X, this->Y, this->Z );
		return buffer;
	};*/
	float		Distance(FVector v);
	float		Dot(FVector pStart, FVector pEnd);
	bool		InAngle(FVector pStart, FVector pEnd, FVector pRotation, int nAngle);
	int			round(float fValue);
	FVector2D	GetAngleToOrigin(FRotator ViewAngles, FVector vec_Start, FVector vec_End);
	//static	float		GetDistance(centity_t* pEntity, FVector Location);
	//static	bool		WorldToScreen(FVector vec_Location, FVector& vec_Return);

	bool IsValid ();
};

struct Matrix
{
	FVector Forward;
	FVector Right;
	FVector Up;

	Matrix ();
	Matrix ( FVector _Forward, FVector _Right, FVector _Up );
};
struct FQuat
{
	float x;
	float y;
	float z;
	float w;
};

struct FTransform
{
	FQuat rot;
	FVector translation;
	char pad[4];
	FVector scale;
	char pad1[4];

	D3DMATRIX ToMatrixWithScale()
	{
		D3DMATRIX m;
		m._41 = translation.X;
		m._42 = translation.Y;
		m._43 = translation.Z;

		float x2 = rot.x + rot.x;
		float y2 = rot.y + rot.y;
		float z2 = rot.z + rot.z;

		float xx2 = rot.x * x2;
		float yy2 = rot.y * y2;
		float zz2 = rot.z * z2;
		m._11 = (1.0f - (yy2 + zz2)) * scale.X;
		m._22 = (1.0f - (xx2 + zz2)) * scale.Y;
		m._33 = (1.0f - (xx2 + yy2)) * scale.Z;

		float yz2 = rot.y * z2;
		float wx2 = rot.w * x2;
		m._32 = (yz2 - wx2) * scale.Z;
		m._23 = (yz2 + wx2) * scale.Y;

		float xy2 = rot.x * y2;
		float wz2 = rot.w * z2;
		m._21 = (xy2 - wz2) * scale.Y;
		m._12 = (xy2 + wz2) * scale.X;

		float xz2 = rot.x * z2;
		float wy2 = rot.w * y2;
		m._31 = (xz2 + wy2) * scale.Z;
		m._13 = (xz2 - wy2) * scale.X;

		m._14 = 0.0f;
		m._24 = 0.0f;
		m._34 = 0.0f;
		m._44 = 1.0f;

		return m;
	}
};
extern FVector FVec;
#endif