;******************************************************************************
;* RC5_ALGORITHM:
;******************************************************************************

;*******************************Define Variables*******************************
.EQU R = 8
.EQU T = 18
.EQU W = 16
.EQU U = 2
.EQU B = 12
.EQU C = 6
.EQU N = 54
.EQU PL = 0xe1
.EQU PH = 0xb7
.EQU QL = 0x37
.EQU QH = 0x9e

.MACRO INPUT_A
	.DEF AL = R16
	.DEF AH = R17
		LDI AL, @1         ;LBYTE_INPUT
		LDI AH, @0         ;HBYTE_INPUT
.ENDMACRO

.MACRO INPUT_B
	.DEF BL = R18
	.DEF BH = R19
		LDI BL, @1         ;LBYTE_INPUT
		LDI BH, @0         ;HBYTE_INPUT
.ENDMACRO

.MACRO SECRET_KEY
	.EQU BY0 = 0x80
	.EQU BY1 = 0x81
	.EQU BY2 = 0x82
	.EQU BY3 = 0x83
	.EQU BY4 = 0x84
	.EQU BY5 = 0x85
	.EQU BY6 = 0x86
	.EQU BY7 = 0x87
	.EQU BY8 = 0x88
	.EQU BY9 = 0x89
	.EQU BY10 = 0x8A
	.EQU BY11 = 0x8B
		LDI R20, @11
		STS BY0, R20
		LDI R20, @10
		STS BY1, R20
		LDI R20, @9
		STS BY2, R20
		LDI R20, @8
		STS BY3, R20
		LDI R20, @7
		STS BY4, R20
		LDI R20, @6
		STS BY5, R20
		LDI R20, @5
		STS BY6, R20
		LDI R20, @4
		STS BY7, R20
		LDI R20, @3
		STS BY8, R20
		LDI R20, @2
		STS BY9, R20
		LDI R20, @1
		STS BY10, R20
		LDI R20, @0
		STS BY11, R20
.ENDMACRO


;*********************************Operations***********************************
.MACRO XOR_WORD             ;Return the registers that save result of operations
		EOR @1, @3
		EOR @0, @2
.ENDMACRO

.MACRO ADD_WORD             ;Return the registers which save result of operations
		ADD @1, @3
		ADC @0, @2
.ENDMACRO

.MACRO SUB_WORD             ;Return the registers which save result of operations
		SUB @1, @3
		SBC @0, @2
.ENDMACRO

.MACRO ROTL_WORD
		LDI R31, @2         ;Only the lg(w) low-order bits of B are used to determine the rotation amount. 
	ROTL:
		ROL @1
		BST @0, 7
		ROL @0
		BLD @1, 0
		DEC R31
		BRNE ROTL
.ENDMACRO

.MACRO ROTR_WORD
		LDI R31, @2          ;Only the lg(w) low-order bits of B are used to determine the rotation amount.
	ROTR:
		ROR @0
		BST @1, 0
		ROR @1
		BLD @0, 7
		DEC R31
		BRNE ROTR
.ENDMACRO

.MACRO MODULU
	LOOP:
		SUBI @0, @1
		CPI  @0, @1          ;Compare with Immediate; Set C flag if the absolute value of K is larger than the absolute value of Rd; cleared otherwise.
		BRSH LOOP            ;branch if C = 0
.ENDMACRO


;*********************************RC5_ENCRYPT**********************************
.MACRO RC5_ENCRYPT
		;Initial inputs
		INPUT_A @0, @1
		INPUT_B @2, @3

		;Adjust X pointer
		LDI XL, 0x94           ;Position of S[2]
		LDI XH, 0x00

		;Initialling A and B
		ADD_WORD AH, AL, S0H, S0L
		ADD_WORD BH, BL, S1H, S1L

		;Startting the loop
		LDI R20, 7
	LOOP:
		;Compute A
		LDI R23, 0x0F
		AND R23, BL

		LD R21, X+
		LD R22, X+
		XOR_WORD AH, AL, BH, BL
		ROTL_WORD AH, AL, R23  ;Only the lg(w) low-order bits of B are used to
		                       ;determine the rotation amount.
		ADD_WORD AH, AL, R22, R21

		;Compute B
		LDI R24, 0x0F
		AND R24, AL

		LD R21, X+
		LD R22, X+
		XOR_WORD BH, BL, AH, AL
		ROTL_WORD BH, BL, R24  ;Only the lg(w) low-order bits of B are used to
		                       ;determine the rotation amount.
		ADD_WORD BH, BL, R22, R21

		;Loop controling
		DEC R20
		BRNE LOOP
.ENDMACRO


;********************************RC5_DECRYPT***********************************
.MACRO RC5_DECRYPT
		INPUT_A @0, @1         ;RETURN AH, AL
		INPUT_B @2, @3         ;RETURN BH, BL

		;Adjust X pointer
		LDI XL, 0xA7           ;Position of S[2*i+1], where i=8
		LDI XH, 0x00

		;Startting the loop {
		LDI R20, 7
	LOOP:
		;Compute B {
		LDI R24, 0x0F
		AND R24, AL

		LD R22, X             
		LD R21, -X
		SUB_WORD BH, BL, R22, R21
		ROTR_WORD BH, BL, R24
		XOR_WORD BH, BL, AH, AL
		;}

		;Compute A {
		LDI R23, 0x0F
		AND R23, BL

		LD R22, -X
		LD R21, -X
		SUB_WORD AH, AL, R22, R21
		ROTR_WORD AH, AL, R23
		XOR_WORD AH, AL, BH, BL
		;}

		;Correct the X pointer of the next loop 
		LD R22, -X
		
		;Loop controling
		DEC R20
		BRNE LOOP
		;}
.ENDMACRO


;**********************************RC5_SETUP***********************************
.MACRO RC5_SETUP
	;First step: {
	;Here because we have an organized code this step can be regarded as renaming step.
	.EQU LW0L = BY0             ;Position 0x60
	.EQU LW0H = BY1             ;Position 0x61
	;}

	;Second step: {
	.EQU S0L = 0x90
	.EQU S0H = 0x91
	.EQU S1L = 0x92
	.EQU S1H = 0x93

		;Adjust X pointer
		LDI XL, 0x90
		LDI XH, 0x00

		;Initializing S[0].
		LDI R17, PL
		LDI R18, PH
		STS S0L, R17
		STS S0H, R18

		;Startting the loop of second step.
		LDI R16, T
	LOOP:
		LDI R17, QL
		LDI R18, QH

		LD R19, X+
		LD R20, X+
		ADD_WORD R20, R19, R18, R17
		ST X+, R19
		ST X, R20
		LD R25, -X

		DEC R16
		BRNE LOOP
	;}

	;Third step: {
	.DEF AL = R17
	.DEF AH = R18
	.DEF BL = R19
	.DEF BH = R20
	.DEF i = R21
	.DEF j = R22
		;Adjust X and Y pointer
		LDI XL, S0L
		LDI XH, S0H
		LDI YL, LW0L
		LDI YH, LW0H
		;Load immediate the initiale values
		LDI AH, 0x00
		LDI AL, 0x00
		LDI BH, 0x00
		LDI BL, 0x00
		LDI i, 0x00
		LDI j, 0x00

		;Constructe the body of key_expansion {
		LDI R16, N
	LOOP:
		;Get the A value {
		LDD R23, X+i
		LDD R24, X+i+1
		ADD_WORD R24, R23, AH, AL
		ADD_WORD R24, R23, BH, BL
		ROTL_WORD R24, R23, 3
		STD X+i, R23
		STD X+i+1, R24
		MOVW AH:AL, R24:R23
		;Adjust the i value
		LDI R25, 0x01
		ADD i, R25
		MODULU i, T
		;}

		;Get the B value {
		LDD R23, Y+i
		LDD R24, Y+i+1
		ADD_WORD R24, R23, AH, AL
		ADD_WORD R24, R23, BH, BL
		ADD BL, AL
		LDI R25, 0x0F
		AND R25, BL
		ROTL_WORD R24, R23, R25
		STD Y+i, R23
		STD Y+i+1, R24
		MOVW BH:BL, R24:R23
		;Adjust the j value
		LDI R25, 0x01
		ADD j, R25
		MODULU j, C
		;}

		;Loop controling
		DEC R16
		BRNE LOOP
		;}
	;}
.ENDMACRO
