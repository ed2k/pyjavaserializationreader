import dpkt.dpkt as dpkt
import sys

STREAM_MAGIC = 0xacde
STREAM_VERSION = 5
TC_NULL = 0x70
TC_REFERENCE =	0x71;
TC_CLASSDESC = 	0x72;
TC_OBJECT = 	0x73;
TC_STRING = 	0x74;
TC_ARRAY = 	0x75;
TC_CLASS = 	0x76;
TC_BLOCKDATA = 	0x77;
TC_ENDBLOCKDATA =	0x78;
TC_RESET = 	0x79;
TC_BLOCKDATALONG= 0x7A;
TC_EXCEPTION = 	0x7B;
TC_LONGSTRING = 	0x7C;
TC_PROXYCLASSDESC =	0x7D;
TC_ENUM =		0x7E;
TC_MAX = 		0x7E;

baseWireHandle = 0x7e0000;

SC_WRITE_METHOD = 0x01;
SC_SERIALIZABLE = 0x02;
SC_EXTERNALIZABLE = 0x04;
SC_BLOCK_DATA = 0x08;  

SC_ENUM = 0x10;

class StackContent:
    obj = None
    index = 0
    def className(self):
        if self.obj is None: return None
        if type(self.obj) == type(NewArray()): return self.obj.classDesc
        return self.obj.className
    
    
class WorkingTable:    
    classdesc_table = {}
    depth = 0
    handle_cnt = -1
    #give us a way to know where are we in the obj tree, after
    #runing out of data, StackContent = (TC, position)
    call_stack = []     
    left_over = '' ;#unprocessed data
    saved_handle_cnt = -1
    prev_obj = None
    
    def getClassDesc(self,handle):
        return self.classdesc_table[handle]      

        #pop and save the return obj, working backward
    def stack_back(self):    
        self.prev_obj = self.call_stack.pop().obj
        print 'stack prevobj',type(self.prev_obj)

    #each class is defined once,
    #TODO classname existence check or
    # we need to make sure same obj is saved once, when stream accross
    # diff packets 
    def store_class(self,classDesc):
        self.handle_cnt += 1   
        self.pr( hex(self.handle_cnt),end=' ')
        self.classdesc_table[self.handle_cnt] = classDesc
        #self.call_stack[-1].index = 1
        #self.saved_handle_cnt = self.handle_cnt        
        # this is the handle value, it will be used to reference each object

    def save(self,idx,buf):
        self.call_stack[-1].index = idx
        self.left_over = buf
        self.saved_handle_cnt = self.handle_cnt

    def stack_push(self,obj):
        stack = StackContent()
        stack.obj = obj
        self.saved_handle_cnt = self.handle_cnt
        self.call_stack.append(stack)        
    def stack_pop(self):
        self.call_stack.pop()
        
    def prdep(self, *args, **kwargs):
        if not 'sep' in kwargs.keys():  sep = ' '
        else : sep = kwargs['sep']
        if not 'end' in kwargs.keys():  end = '\n'
        else : end = kwargs['end']
        sys.stdout.write('    '*len(self.call_stack))
        sys.stdout.write(sep.join([str(x) for x in args]))
        sys.stdout.write(end)

    def pr(self, *args, **kwargs):
        if not 'sep' in kwargs.keys():  sep = ' '
        else : sep = kwargs['sep']
        if not 'end' in kwargs.keys():  end = '\n'
        else : end = kwargs['end']
        sys.stdout.write(sep.join([str(x) for x in args]))
        sys.stdout.write(end)

#if _debug_ is None:
#    _debug_ = WorkingTable()

 
class Breakable(dpkt.Packet):  
    def unpack(self, buf):
        #_debug_.left_over = buf
        #stack = StackContent()
        #stack.obj = self
        #_debug_.call_stack.append(stack)
        #print 'push',len(_debug_.call_stack),type(self)
        dpkt.Packet.unpack(self, buf)
        


class NewHandle:
    def __init__(self,obj):
        _debug_.store_class(obj)

                 
class Jint(dpkt.Packet):
    __hdr__ = [
        ('value','I',0)]
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = ''
        
class UTF(dpkt.Packet):
    __hdr__ = [
        ('slen','H',0)]
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data =  buf[2:2+self.slen]
        
class NewString(Breakable):
    __hdr__ = [('tc','B',TC_STRING),
        ('slen','H',0)]
    def unpack(self, buf):
        Breakable.unpack(self, buf)
        self.data =  buf[3:3+self.slen]
        if len(self.data) != self.slen:
            raise dpkt.NeedData
        NewHandle(self)
        

class NullReference(dpkt.Packet):
    __hdr__ = [('tc','B',TC_NULL)]
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        _debug_.pr( 'TC_NULL')
        self.data = ''

        
class Fields(dpkt.Packet):
    __hdr__ = [
        ('count','H',0)]
    ftypes = []
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        offset = 2
        self.ftypes = []
        _debug_.prdep('count ', self.count)
        for i in xrange(self.count):
            typecode = buf[offset]
            offset += 1
            if typecode in 'BCDEFIJSZ':
                s = UTF(buf[offset:])
                offset += len(s)
                _debug_.prdep( i,'field',typecode,[s.data])
                self.ftypes.append((typecode,s.data))
            elif typecode in '[L':
                s = UTF(buf[offset:])
                offset += len(s)
                _debug_.prdep(i,'field',typecode,[s.data],end=' ')    
                #only NewString and PrevObject is possible                 
                className1 = Content(buf[offset:])
                offset += len(className1)
                # seems no need to save the exact object info
                self.ftypes.append((typecode,s.data))
            else:
                _debug_.pr( 'sth wrong',typecode)
                offset += 1000
        self.data = buf[2:offset]




def Content(buf):
    tc = ord(buf[0])
    obj = None

    _debug_.depth += 1       

    if tc == TC_OBJECT:
        obj = NewObject(buf)
    elif tc == TC_BLOCKDATA:
        obj = Blockdata(buf)
    elif tc == TC_CLASS:
        obj = NewClass(buf)
    elif tc == TC_ARRAY:
        obj = NewArray(buf)
    elif tc == TC_STRING:
        obj = NewString(buf)
        _debug_.pr( 'content:',[obj.data])
    elif tc == TC_CLASSDESC:
        obj = NewClassDesc(buf)
    elif tc == TC_REFERENCE:
        obj = PrevObject(buf)
        _debug_.pr( 'conref:', hex(obj.handle))
    elif tc == TC_ENUM:
        obj = NewEnum(buf)
    elif tc == TC_NULL:
        obj = NullReference(buf)
    else:
        _debug_.pr( 'Content unknown',tc,dpkt.hexdump(buf[:64]))

    _debug_.depth -= 1       
    return obj


class PrevObject(dpkt.Packet):
    __hdr__ = ( ('tc','B',TC_REFERENCE),
        ('handle','I',0x7e0000))
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.handle = self.handle - baseWireHandle
        self.data = ''
        
class Blockdata(dpkt.Packet):
    __hdr__ = [ ('tc','B',TC_BLOCKDATA),
        ('size','B',1)]
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.tc != TC_BLOCKDATA:
            _debug_.pr( self.tc, 'blockdata long not impl')
        self.data = buf[2:2+self.size]
        _debug_.pr( 'blockdata',self.size,dpkt.hexdump(self.data))
        


class NewClassDesc(Breakable):
    __hdr__ = [
        ('tc','B',TC_CLASSDESC)]
    className = None
    fields = None
    super = None
    flags = 0    
    def unpack(self, buf):
        Breakable.unpack(self, buf)        
        if self.tc != TC_CLASSDESC:
            _debug_.pr( self.tc,'NewClassDesc exception',dpkt.hexdump(buf[0:64]))
        offset = 1

        className = UTF(buf[offset:])
        _debug_.pr( 'class',[className.data])
        self.className = className.data
        offset = 1+len(className)
        NewHandle(self)
        self.data = buf[self.__hdr_len__:offset]
        buf = buf[offset:]    
        offset = 0

        serialVersionUID = buf[offset:8+offset]
        #_debug_.pr( 'serialVersionUID',Jint(serialVersionUID).value,dpkt.hexdump(serialVersionUID)
        offset += 8
        #classDescInfo
        self.flags = ord(buf[offset]); 
        offset+=1
        self.fields = Fields(buf[offset:])
        offset += len(self.fields)
        if ord(buf[offset]) != TC_ENDBLOCKDATA:
            _debug_.pr( 'not implement class annotation', dpkt.hexdump(buf[0:offset+32]))
        offset += 1
        # superClassDesc, classDesc, 
        _debug_.pr( 'super',end=' ')
        self.data = self.data+buf[:offset]        
        buf = buf[offset:]    
        offset = 0

        self.super = Content(buf[offset:])
        offset += len(self.super)

        if type(self.super) == type(PrevObject()):
            self.super = _debug_.getClassDesc(self.super.handle)
            _debug_.pr( self.super.className)

        self.data = self.data+buf[:offset]

    def iterateData(self,buf):
        _debug_.stack_push(self)   
        _debug_.save(0,buf)
        if type(self.super) is type(NullReference()):
            offset = 0
        else:
            offset = self.super.iterateData(buf)

        classname = self.className
        formats = self.fields.ftypes
        _debug_.prdep(len(formats),'data of',classname)
        idx = 1        
        for (f,vname) in formats:
            _debug_.prdep( cl2(classname),idx,[f],vname,end=' ')
            _debug_.save(idx,buf[offset:])
            offset += GenericObject(f,buf[offset:])
            idx +=1
        _debug_.stack_pop()
        
        #TODO: protect here        
        if self.flags == 0x3 :
            while(ord(buf[offset]) != TC_ENDBLOCKDATA):
               obj = Content(buf[offset:])
               offset += len(obj)                                  
            offset +=1

        return offset

    def unpack_resume(self,buf):
        offset = 0
        classname = self.className
        formats = self.fields.ftypes       
        idx = _debug_.call_stack[-1].index        
        if (not _debug_.prev_obj is None):
            idx += 1
        if idx <= len(formats):
            _debug_.prdep(idx,'in',len(formats),'data of',classname)
            
        for (f,vname) in formats[idx-1:]:
            _debug_.prdep( cl2(classname),idx,[f],vname,end=' ')
            _debug_.save(idx,buf[offset:])
            offset += GenericObject(f,buf[offset:])
            idx +=1
                
        if self.flags == 0x3 :
            while(ord(buf[offset]) != TC_ENDBLOCKDATA):
               obj = Content(buf[offset:])
               offset += len(obj)                                  
            offset +=1

        _debug_.prev_obj = _debug_.call_stack.pop()

        return offset    

def GenericObject(format,buf):
    code = format[0]
    size = -1
    if code in 'BZ': size = 1
    elif code in 'SC': size = 2
    elif code in 'FI': size = 4
    elif code in 'DJ': size = 8
        
    if size > 0:
        value = buf[:size]
        _debug_.pr( dpkt.hexdump(value))
        return size
    else:
        obj  = Content(buf)
        return len(obj)

class NewArray(Breakable):
    __hdr__ = [('tc','B',TC_ARRAY)]
      
    def unpack(self, buf):
        Breakable.unpack(self, buf)
        offset = 1

        self.classDesc = Content(buf[offset:])
        offset += len(self.classDesc)
        if type(self.classDesc) == type(PrevObject()):
            self.classDesc = _debug_.getClassDesc(self.classDesc.handle)

        NewHandle(self)
       
        offset += self.decode_array_data(buf[offset:],self.classDesc)
        self.data = buf[1:offset]
        
    def decode_array_data(self,buf,classdesc):
        size = Jint(buf)
        offset = len(size)
        self.size = size.value
        #assert first char of className is [ 
        _debug_.prdep( 'arr size',size.value, classdesc.className)
        _debug_.stack_push(self)   
        for i in xrange(size.value):
            _debug_.prdep( classdesc.className[1:],i,end=' ')
            _debug_.save(i,buf[offset:])
            offset += GenericObject(classdesc.className[1:],buf[offset:])
        _debug_.stack_pop()
        return offset
    def unpack_resume(self,buf):
        offset = 0 
        className = self.classDesc.className
        #assert first char of className is [ 
        _debug_.prdep( 'arr size',self.size, className)
        idx = _debug_.call_stack[-1].index
        if (not _debug_.prev_obj is None):
            idx += 1
        for i in xrange(idx,self.size):
            _debug_.prdep( className[1:],i,end=' ')
            _debug_.save(i,buf[offset:])
            offset += GenericObject(className[1:],buf[offset:])

        _debug_.prev_obj = _debug_.call_stack.pop()
        return offset
    
class NewEnum(Breakable):
    __hdr__ = [('tc','B',TC_ENUM)]
    def unpack(self,buf):
        Breakable.unpack(self, buf)
        offset = 1
        self.classDesc = Content(buf[offset:])
        offset += len(self.classDesc)
        classname = self.classDesc.className
        NewHandle(self)     
        name = NewString(buf[offset:])      
        _debug_.pr( 'enum_name',[name.data]  )
        offset += len(name)
        self.data = buf[1:offset]
        
                        
def cl2(classname):    return '.'.join(classname.split('.')[-2:])
class NewObject(Breakable):
    __hdr__ = [
        ('tc','B',TC_OBJECT)]
    classDesc = None
               
    def unpack(self, buf):
        Breakable.unpack(self, buf)
        offset = 1
        formats = []
        # has to be null,ref or newclassdesc
        self.classDesc = Content(buf[offset:])
        offset += len(self.classDesc)
        #_debug_.pr( 'type',type(self.classDesc)
        if type(self.classDesc) == type(PrevObject()):
            self.classDesc = _debug_.getClassDesc(self.classDesc.handle)
        
        NewHandle(self)
           
        #classdata decoding
        offset += self.classDesc.iterateData(buf[offset:])
       
        self.data = buf[1:offset]


class JSER(dpkt.Packet):
    __hdr__ = (
        ('magic','H',STREAM_MAGIC),
        ('version','H',1))

    # assume only one object 
    def unpack(self, buf):
        if len(_debug_.call_stack) > 0:
            buf = _debug_.left_over+buf        
            _debug_.handle_cnt = _debug_.saved_handle_cnt
            _debug_.prev_obj = None
            offset = 0
            while len(_debug_.call_stack) > 0:
                offset += _debug_.call_stack[-1].obj.unpack_resume(buf[offset:])
                        
        else:
            dpkt.Packet.unpack(self, buf)
            offset = self.__hdr_len__
            obj = Content(buf[offset:])
            offset += len(obj)
            #if offset < len(buf):
            #    _debug_.pr( dpkt.hexdump(buf[offset-16:])  )           
            
        

if __name__ == '__main__':
    import dpkt,sys
    _debug_ = WorkingTable()
    p = JSER(file(sys.argv[1]).read())

