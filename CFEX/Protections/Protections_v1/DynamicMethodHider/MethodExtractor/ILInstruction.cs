using ObfuscationCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace ObfuscationCore.Extractor
{
 public abstract class ILInstruction
 {
  protected Int32 m_offset;
  protected OpCode m_opCode;

  internal ILInstruction(Int32 offset, OpCode opCode)
  {
   this.m_offset = offset;
   this.m_opCode = opCode;
  }

  public Int32 Offset { get { return m_offset; } }
  public OpCode OpCode { get { return m_opCode; } }

  public abstract void Accept(InstructionVisitor vistor);
 }

 public class UnhandledInstruction : ILInstruction
 {

  internal UnhandledInstruction(Int32 offset, OpCode opCode)
      : base(offset, opCode)
  {

  }

  public override void Accept(InstructionVisitor vistor) { }
 }



 public class InlineFieldInstruction : ILInstruction
 {
  ITokenResolver m_resolver;
  Int32 m_token;
  FieldInfo m_field;

  internal InlineFieldInstruction(ITokenResolver resolver, Int32 offset, OpCode opCode, Int32 token)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public FieldInfo Field
  {
   get
   {
    if (m_field == null)
    {
     m_field = m_resolver.AsField(m_token);
    }
    return m_field;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineFieldInstruction(this); }
 }
 public class InlineMethodInstruction : ILInstruction
 {
  private ITokenResolver m_resolver;
  private Int32 m_token;
  private MethodBase m_method;

  internal InlineMethodInstruction(Int32 offset, OpCode opCode, Int32 token, ITokenResolver resolver)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public MethodBase Method
  {
   get
   {
    if (m_method == null)
    {
     m_method = m_resolver.AsMethod(m_token);
    }
    return m_method;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineMethodInstruction(this); }
 }
 public class InlineTypeInstruction : ILInstruction
 {
  private ITokenResolver m_resolver;
  private Int32 m_token;
  private Type m_type;

  internal InlineTypeInstruction(Int32 offset, OpCode opCode, Int32 token, ITokenResolver resolver)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public Type Type
  {
   get
   {
    if (m_type == null)
    {
     m_type = m_resolver.AsType(m_token);
    }
    return m_type;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineTypeInstruction(this); }
 }
 public class InlineSigInstruction : ILInstruction
 {
  private ITokenResolver m_resolver;
  private Int32 m_token;
  private byte[] m_signature;

  internal InlineSigInstruction(Int32 offset, OpCode opCode, Int32 token, ITokenResolver resolver)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public byte[] Signature
  {
   get
   {
    if (m_signature == null)
    {
     m_signature = m_resolver.AsSignature(m_token);
    }
    return m_signature;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineSigInstruction(this); }
 }
 public class InlineTokInstruction : ILInstruction
 {
  private ITokenResolver m_resolver;
  private Int32 m_token;
  private MemberInfo m_member;

  internal InlineTokInstruction(Int32 offset, OpCode opCode, Int32 token, ITokenResolver resolver)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public MemberInfo Member
  {
   get
   {
    if (m_member == null)
    {
     m_member = m_resolver.AsMember(Token);
    }
    return m_member;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineTokInstruction(this); }
 }

 public class InlineStringInstruction : ILInstruction
 {
  private ITokenResolver m_resolver;
  private Int32 m_token;
  private String m_string;

  internal InlineStringInstruction(Int32 offset, OpCode opCode, Int32 token, ITokenResolver resolver)
      : base(offset, opCode)
  {
   this.m_resolver = resolver;
   this.m_token = token;
  }

  public String String
  {
   get
   {
    if (m_string == null) m_string = m_resolver.AsString(Token);
    return m_string;
   }
  }
  public Int32 Token { get { return m_token; } }

  public override void Accept(InstructionVisitor vistor) { vistor.VisitInlineStringInstruction(this); }
 }




}
