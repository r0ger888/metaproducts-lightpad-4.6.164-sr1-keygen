
comment */
	
	the modulus and the private key exp are the same as the ones from Download Express.
	notice that it doesn't have that unlimited site licence type (10000) since it only
	has the different amount of copies chosen (maximum 4 digits).
	
*/

include biglib.inc
includelib biglib.lib

include base64.asm

GenKey		PROTO	:DWORD

.data
ExpN 		db "2AE23A62A605CAB8A6A8E063112DECF900B91B531BEBEC66B57A8A3C78BDA57BE2D3E14B6BFFBBF8C46188FD02D57",0
ExpD 		db "20E3260B896F5FAC848376B202F6C9899CB858F03FB58A89A3E5DA679C6D8C8091E2AD95D16F6EC1C6EA218DB2F61",0
AppLabel	db "WS40",0
OneByte		db 01h,0
StartKey	db "dqma",0
EndKey		db "amqd",0
NoName		db "insert ur name.",0
NoCopies	db "how many copies ?",0
TooLong		db "name too long.",0
FinalBuffer db 256 dup(0)
NameBuffer	db 256 dup(0)
CpsBuffer	db 256 dup(0)

.data?
_N			dd ?
_D			dd ?
_C		    dd ?
_M  		dd ?
RSAEnk		db 256 dup(?)
Base64Bfr	db 256 dup(?)

.code
GenKey proc hWin:DWORD

	; get the whole name string.
	invoke GetDlgItemText,hWin,IDC_NAME,addr NameBuffer, sizeof NameBuffer
	or eax,eax
	jz no_name
	cmp eax,25
	jg name_too_long
	
	; and the string of the nr of copies
	invoke GetDlgItemText,hWin,IDC_NRCOPY,addr CpsBuffer, sizeof CpsBuffer
	or eax,eax
	jz no_copynr
	
	; initialize the string for RSA-370 decryption
	mov byte ptr [RSAEnk],7
	invoke lstrcat,offset RSAEnk,offset AppLabel	; WS40 (...wasnt that for Web Studio perhaps ??)
	invoke lstrcat,offset RSAEnk,offset OneByte		; 01h
	invoke lstrcat,offset RSAEnk,offset NameBuffer	; ur name
	invoke lstrcat,offset RSAEnk,offset OneByte		; 01h
	invoke lstrcat,offset RSAEnk,offset CpsBuffer	; nr. of copies (instead of 10000 which was unlimited site licence)
	
	; initialize biglib for modulus and the private key exponent, and for the plaintext and chipertext.
	invoke _BigCreate,0
	mov _N,eax
	invoke _BigCreate,0
	mov _D,eax
	invoke _BigCreate,0
	mov _C,eax
	invoke _BigCreate,0
	mov _M,eax
	
	; set exponents with _BigIn and calculate the length of the RSAEnk variable
	invoke _BigIn,offset ExpN,16,_N
	invoke _BigIn,offset ExpD,16,_D
	invoke lstrlen,offset RSAEnk
	
	; set the bytes for the padded plaintext
	invoke _BigInBytes,offset RSAEnk,eax,256,_M
	
	; _C = _M^_D mod _N
	invoke _BigPowMod,_M,_D,_N,_C
	
	;set RSA-370 bytes for the RSA buffer
	invoke _BigOutBytes,_C,256,offset RSAEnk
	
	; encode them with base64
	push offset Base64Bfr
	push eax
	push offset RSAEnk
	call Base64Enk
	
	; "dqma" + final string made of RSA-370 & Base64 + "amqd"
	invoke lstrcat,offset FinalBuffer,offset StartKey
	invoke lstrcat,offset FinalBuffer,offset Base64Bfr
	invoke lstrcat,offset FinalBuffer,offset EndKey
	
	; final result in the textbox :p
	invoke SetDlgItemText,hWin,IDC_SERIAL,offset FinalBuffer
	
	; clear RSA buffers.
	call Clean
	ret
	
no_name:
	invoke SetDlgItemText,hWin,IDC_SERIAL,addr NoName
	ret
	
name_too_long:
	invoke SetDlgItemText,hWin,IDC_SERIAL,addr TooLong
	ret
	
no_copynr:
	invoke SetDlgItemText,hWin,IDC_SERIAL,addr NoCopies
	ret
GenKey endp
Clean proc

	invoke RtlZeroMemory,offset FinalBuffer,sizeof FinalBuffer
	invoke RtlZeroMemory,offset RSAEnk,sizeof RSAEnk
	invoke RtlZeroMemory,offset Base64Bfr,sizeof Base64Bfr
	invoke RtlZeroMemory,offset NameBuffer,sizeof NameBuffer
	invoke RtlZeroMemory,offset CpsBuffer,sizeof CpsBuffer
	invoke _BigDestroy,_N
	invoke _BigDestroy,_D
	invoke _BigDestroy,_C
	invoke _BigDestroy,_M
	ret
	
Clean endp