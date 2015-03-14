
```
-- FOO PROTOCOL
--

FOO-PROTOCOL DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

-- General definitions
Bits4 ::= INTEGER(0..15)
Byte ::= INTEGER (0..255)
Char ::= INTEGER (0..255)
Bytes2 ::= OCTET STRING(SIZE(2))
Bytes4 ::= OCTET STRING(SIZE(4))
Bytes8 ::= OCTET STRING(SIZE(8))
PrevObject ::= OCTET STRING(SIZE(4))
UTF ::= OCTET STRING(SIZE(0..65535))
NewString ::= OCTET STRING(SIZE(0..65535))
DUMMY ::= SEQUENCE {
  guint8 Byte,
  guint16 Bytes2,
  guint32 Bytes4,
  guint64 Bytes8
}

-- move up to declaure first, then used by Fields
PrimitiveDesc 	::= SEQUENCE {      
      heading-4bits Bits4,
      typecode CHOICE {
		x40 NULL, x41 NULL,
		byte UTF,
		char UTF,
		double UTF,
		x45 NULL, 
		float UTF, 
		x47 NULL, x48 NULL,
		integer UTF,
		long UTF, 
		array ObjectDesc, --should be 0x5b for array, 0x4b never happen
		object ObjectDesc
	}
}
NewArray::= SEQUENCE {
	classDesc ClassDesc,
	newHandle NewHandle,
	arrvalues ANY
}
NewEnum::= SEQUENCE {
	classDesc ClassDesc,
	newHandle NewHandle,
    tc-string Byte,
	constName NewString
}

Content ::= SEQUENCE {      
      heading-4bits Bits4,
      con-tc CHOICE {
		null NULL,
     	ref PrevObject,
		cldesc NewClassDesc,
		obj NewObject,
		str NewString,
		arr NewArray,
		class RaiseException,
		blockdata OCTET STRING (SIZE(0..255)),
		x78 RaiseException,
		tc-reset RaiseException,
		blockdatalong OCTET STRING (SIZE(0..65535)),
		exception RaiseException,
		x7c RaiseException,
		tc-proxyclassdesc RaiseException,
		enum NewEnum
		}
}

-- only null, ref and new cldesc are possible
ClassDesc ::= SEQUENCE {      
      heading-4bits Bits4,
      cldesc-tc CHOICE {
		cldesc-null NULL,
     	cldesc-ref PrevObject,
		cldesc-newcl NewClassDesc,
		newObject NewObject,
		newString NewString,
		newArray NewArray,
		newClass RaiseException,
		blockdata OCTET STRING (SIZE(0..255)),
		x78 RaiseException,
		tc-reset RaiseException,
		blockdatalong OCTET STRING (SIZE(0..65535)),
		exception RaiseException,
		x7c RaiseException,
		tc-proxyclassdesc RaiseException,
		enum NewEnum
		}
}

-- 2byte count, then count number of FieldDesc
Fields2 ::=  SEQUENCE {
	count FieldsCount, 
	fieldDesc PrimitiveDesc
	}
FieldsCount ::= INTEGER(0..65535)	

ObjectDesc ::=  SEQUENCE {
      fieldName UTF,
	  className Content
}


--ClassDescInfo blend into NewClassDesc
NewClassDesc ::=  SEQUENCE { 
	name UTF,
	uid OCTET STRING(SIZE(8)),
	flags Byte,
	fields ANY,
	classAnnotation Byte, -- TODO, 0x78 and contents
	extends ClassDesc
}

NewHandle ::= NULL
       
NewObject ::=  SEQUENCE {
	classDesc ClassDesc,
	newHandle NewHandle,
	classdata ANY
}

RaiseException ::=  Byte

-- make decoder run through contents of contents, see cnf file
JSER-MESSAGE ::= SEQUENCE { 
      magic Bytes2 , --0xaced
      version Bytes2,
      contents ANY
}
    

END

```