#labels c,packet,wireshark,jser,template
{{{
/* packet-jser.c
 * Routines for jser packet dissection
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-per.h>

//#include "packet-jser.h"

#define PNAME  "JSER"
#define PSNAME "Java SERialized object"
#define PFNAME "jser" 			// the protocol filter name
#define JSER_PORT 60003    /* UDP port */

#define JSER_STREAM_MAGIC   0xaced
#define JSER_STREAM_VERSION 5

#define JSER_TC_NULL             0x70
#define JSER_TC_REFERENCE        0x71
#define JSER_TC_CLASSDESC        0x72
#define JSER_TC_OBJECT           0x73
#define JSER_TC_STRING           0x74
#define JSER_TC_ARRAY            0x75
#define JSER_TC_CLASS            0x76
#define JSER_TC_BLOCKDATA        0x77
#define JSER_TC_ENDBLOCKDATA     0x78
#define JSER_TC_RESET            0x79
#define JSER_TC_BLOCKDATALONG    0x7A
#define JSER_TC_EXCEPTION        0x7B
#define JSER_TC_ENUM             0x7E
#define JSER_BASE_WIRE_HANDLE    0x7E0000

typedef struct _jser_field_t {
  guint8 *fieldname; //null terminated string
  guint16 len;       //original utf len from protocol, =len(fieldname)+1
  guint8 typecode;
} jser_field_t;

typedef struct _jser_classdesc_t {
  /*char * classname;*/
  // if is_array, typcode is either prim code or obj
  // should be the 2nd character of NewArray classname
  guint8 array_typecode;
  guint32 handle;
  struct _jser_classdesc_t *super; 
  jser_field_t *fields;
  guint16 fields_count;
  guint8 flags;
} jser_classdesc_t;

static dissector_handle_t jser_handle=NULL;
/* place holder for subparameter length */
static int begin_length = -1;
/* Initialize the protocol and registered fields */
static int proto_jser = -1;
static int global_jser_port = JSER_PORT;	

static guint32 jser_handle_cnt = 0;
static GPtrArray* jser_handle2class;
static ep_stack_t jser_stack; 

static jser_classdesc_t* getClassDesc(guint32 handle) {
  return g_ptr_array_index(jser_handle2class, handle);
}
static void store_class(jser_classdesc_t* p){
  //assume handle_cnt increase with array index
  if (p != NULL) p->handle = jser_handle_cnt;
  g_ptr_array_add(jser_handle2class, p);
  // this is the handle value, it will be used to reference each object
  jser_handle_cnt ++;
}

static void *push(jser_classdesc_t* p){ 
  return ep_stack_push(jser_stack,p);
}
static jser_classdesc_t* pop(){ 
  return ep_stack_pop(jser_stack);
}
static jser_classdesc_t* peek(){ 
  return ep_stack_peek(jser_stack);
}

#include "packet-jser-hf.c"

/* Initialize the subtree pointers */
static int ett_jser = -1;

#include "packet-jser-ett.c"


/* 13 Enemerated */
guint32
dissect_per_enumerated(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, guint32 root_num, guint32 *value, gboolean has_extension, guint32 ext_num, guint32 *value_map)
{
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);
	return offset;
}
// forwared declaration
static int
dissect_jser_PrimitiveDesc(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index);
static int
dissect_jser_Content(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index);
static int
iterate_classdata(jser_classdesc_t *p,tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index);
static int
dissect_jser_FieldsCount(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index);

#include "packet-jser-fn.c"

static int
iterate_classdata(jser_classdesc_t* p,tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index){
  guint16 idx;
  jser_field_t *field;
  if (p == NULL) return offset;
  //return offset;
  offset = iterate_classdata(p->super, tvb, offset, actx, tree, hf_index);
  //proto_tree_add_debug_text(tree,"itecd handle %x count %d super %x", p->handle,p->fields_count,p->super);
  // iterate p the class descriptor
  //   loop through p->fields
  for(idx=0, field = p->fields; idx < p->fields_count; idx++,field++){
  //     show each field
    switch (field->typecode) {
      guint8 v8; guint16 v16; guint32 v32; guint64 v64;
	  proto_item	*pi;
      guint8 tc;
      case 'B': case 'Z': 
        v8 = tvb_get_guint8(tvb, (offset>>3));
        //offset = dissect_jser_Byte(tvb, offset, actx, tree, hf_jser_guint8);
    	pi = proto_tree_add_text(tree, tvb, offset>>3, 1, "");
    	proto_item_set_text(pi, "%s: %d", field->fieldname, v8);        
        offset += 8;
		break;
      case 'S': case 'C':
        //offset = dissect_jser_Bytes2(tvb, offset, actx, tree, hf_jser_guint16);
        v16 = tvb_get_ntohs(tvb, (offset>>3));
    	pi = proto_tree_add_text(tree, tvb, offset>>3, 2, "");
    	proto_item_set_text(pi, "%s: %x", field->fieldname, v16);        
        offset += 16;
		break;
      case 'F': case 'I': 
        //offset = dissect_jser_Bytes4(tvb, offset, actx, tree, hf_jser_guint32);
        v32 = tvb_get_ntohl(tvb, (offset>>3));
    	pi = proto_tree_add_text(tree, tvb, offset>>3, 4, "");
    	proto_item_set_text(pi, "%s: %x", field->fieldname, v32);        
        offset += 32;
		break;
      case 'D': case 'J':
        //offset = dissect_jser_Bytes8(tvb, offset, actx, tree, hf_jser_guint64);
        v64 = tvb_get_ntoh64(tvb, (offset>>3));
    	pi = proto_tree_add_text(tree, tvb, offset>>3, 8, "");
    	proto_item_set_text(pi, "%s: %x", field->fieldname, v64);        
        offset += 64;
		break;
      default:{ 
        guint32 byteoffset = offset>>3;
        tc = tvb_get_guint8(tvb, (offset>>3));
        pi = proto_tree_add_text(tree, tvb, byteoffset, 1, "");
        proto_item_set_text(pi, "%s: ", field->fieldname);        

        offset = dissect_jser_Content(tvb, offset, actx, 
            proto_item_add_subtree(pi, ett_jser), hf_jser_className);
        proto_item_set_len(pi,(offset>>3) - byteoffset);
      }
    }     
  }
  if (p->flags == 0x3){
    proto_item *pi;
    guint32 byteoffset = offset>>3;
    guint16 idx = 0;
    while ( tvb_get_guint8(tvb, byteoffset) != JSER_TC_ENDBLOCKDATA ) {
      pi = proto_tree_add_text(tree, tvb, byteoffset, 1, "");
      proto_item_set_text(pi, "content %d: ", idx);
      offset = dissect_jser_Content(tvb, offset, actx, 
        proto_item_add_subtree(pi, ett_jser), hf_jser_className);
      proto_item_set_len(pi,(offset>>3) - byteoffset);
      byteoffset = offset >> 3;
      idx ++;
    }
    pi = proto_tree_add_text(tree, tvb, offset>>3, 1, "endblockdata");
    proto_item_set_text(pi, "TC_ENDBLOCKDATA");            
    offset += 8;
  }
  return offset;
}



/* determine PDU length of protocol foo 
If only dbupdatersp is very big, we can tell from the class name
How about a fuzzy decoder, just decode localized infomation, like just look ahead two or three bytes
*/

static guint get_foo_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 1000)
      return (guint)9437; /* e.g. length is at offset 4 */
    return tvb_reported_length_remaining(tvb, offset);
}

/* The main dissecting routine */
static void dissect_jser(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item      *real_item = NULL;
  proto_tree      *real_tree = NULL;
  int                     offset = 0;
  guint32 buf = tvb_get_ntohl(tvb, 4);
  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);
  //check the length? start with obj newclassdesc
  if ((buf >> 16) == 0x7372) {
     // only show first 255 char
     guint16 strlen = buf & 0xff; 
     guint8 *s = tvb_get_string(tvb, 8, strlen);      
      /* Clear out stuff in the info column */
	 if (check_col(pinfo->cinfo,COL_INFO)) {
        col_clear(pinfo->cinfo,COL_INFO);
        if (strlen <= 32 ) {
           col_add_fstr(pinfo->cinfo, COL_INFO, "%s", s);
        } else {
           // bypass com.ericsson.ql.qdsf.common.QLP_
           col_add_fstr(pinfo->cinfo, COL_INFO, "%s", s+32);
        }
	 }
     g_free(s);
   }

   /* create the foo protocol tree */
   if (tree) {
 	  proto_item	*pi;
      guint16 magic = tvb_get_ntohs(tvb, 0);
      guint16 version = tvb_get_ntohs(tvb, 2);
      asn1_ctx_t asn1_ctx;
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
      //dissect_jser_JSER_MESSAGE(tvb, 0, &asn1_ctx, tree, hf_jser_JSER_MESSAGE_PDU);
      //dissect_JSER_MESSAGE_PDU(tvb, pinfo, real_tree);
      real_item = proto_tree_add_item(tree, proto_jser, tvb, 0, -1, FALSE);
      real_tree = proto_item_add_subtree(real_item, ett_jser);
      pi = proto_tree_add_text(real_tree, tvb, 0, 4, "");
      proto_item_set_text(pi, "Magic 0x%X version %d", magic,version); 
      // init all data
      jser_handle2class = g_ptr_array_new();
      jser_stack = ep_stack_new();
      jser_handle_cnt = 0;
  
      while (tvb_reported_length_remaining(tvb, offset>>3) > 0)    {
        offset = dissect_jser_Content(tvb, 8*4, &asn1_ctx, real_tree, hf_jser_contents);
      }
   }
}
/* The main dissecting routine */
static void dissect_jser2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 magic = tvb_get_ntohs(tvb, 0);
  //TODO: make conversation and let each packet display partion object stream
  if (magic != JSER_STREAM_MAGIC) return;

      if (tvb_reported_length_remaining(tvb, 0) > 1300 &&
          pinfo->can_desegment) {
        //assume large packets can be reassembled, cheat to decide if stream across 
        //multiple tcp packets
        pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
  	  } else {
        dissect_jser(tvb, pinfo, tree);
      }
}


/*--- proto_register_jser -------------------------------------------*/
void proto_register_jser(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-jser-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_jser,
#include "packet-jser-ettarr.c"
  };


  /* Register protocol */
  proto_jser = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_jser, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_jser ---------------------------------------*/
void
proto_reg_handoff_jser(void)
{
    static gboolean inited = FALSE;

    if( !inited ) {

        jser_handle = create_dissector_handle(dissect_jser2,
                                                     proto_jser);
        dissector_add("tcp.port", JSER_PORT, jser_handle);
        dissector_add("udp.port", JSER_PORT, jser_handle);
        dissector_add("tcp.port", 31234, jser_handle);
        dissector_add("udp.port", 31234, jser_handle);

        inited = TRUE;
    }

}

}}}