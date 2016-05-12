import java.io.PrintStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.*;

/** 
This is a TEA password reverser
usage :
Compile : Set your secret key at the end of the file. & compile with "javac teaCrap.java"
Use : "java teaCrap" Passwords you want to reverse in plain text must be store in "teaPass.txt" 
**/
public class teaCrap
  implements Serializable
{
  private static final long serialVersionUID = 1L;
  private static int[] _key;
  private static byte[] _keyBytes;
  protected static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  
  public teaCrap(byte[] key)
  {
    int klen = key.length;
    _key = new int[4];
    if (klen != 16) {
      throw new ArrayIndexOutOfBoundsException(getClass().getName() + ": Key is not 16 bytes");
    }
    int i = 0;
    for (int j = 0; j < klen; i++)
    {
      _key[i] = (key[j] << 24 | (key[(j + 1)] & 0xFF) << 16 | (key[(j + 2)] & 0xFF) << 8 | key[(j + 3)] & 0xFF);j += 4;
    }
    _keyBytes = key;
  }
  
  public teaCrap(int[] key)
  {
    _key = key;
  }
  
  public String toString()
  {
    String tea = getClass().getName();
    return tea = tea + ": Tiny Encryption Algorithm (TEA)  key: " + getHex(_keyBytes);
  }
  
  public int[] encipher(int[] v)
  {
    int y = v[0];
    int z = v[1];
    int sum = 0;
    int delta = -1640531527;
    int n = 32;
    while (n-- > 0)
    {
      y += ((z << 4 ^ z >>> 5) + z ^ sum + _key[(sum & 0x3)]);
      sum += delta;
      z += ((y << 4 ^ y >>> 5) + y ^ sum + _key[(sum >>> 11 & 0x3)]);
    }
    int[] w = new int[2];
    w[0] = y;
    w[1] = z;
    
    return w;
  }
  
  public int[] decipher(int[] v)
  {
    int y = v[0];
    int z = v[1];
    int sum = -957401312;
    int delta = -1640531527;
    int n = 32;
    while (n-- > 0)
    {
      z -= ((y << 4 ^ y >>> 5) + y ^ sum + _key[(sum >>> 11 & 0x3)]);
      sum -= delta;
      y -= ((z << 4 ^ z >>> 5) + z ^ sum + _key[(sum & 0x3)]);
    }
    int[] w = new int[2];
    w[0] = y;
    w[1] = z;
    
    return w;
  }
  
  public String encode(String source)
  {
    return binToHex(encode(padPlaintext(source).getBytes()));
  }
  
  public int[] encode(byte[] b)
  {
    int bLen = b.length;
    byte[] bp = b;
    
    int _padding = bLen % 8;
    if (_padding != 0)
    {
      _padding = 8 - bLen % 8;
      bp = new byte[bLen + _padding];
      System.arraycopy(b, 0, bp, 0, bLen);
      bLen = bp.length;
    }
    int intCount = bLen / 4;
    int[] r = new int[2];
    int[] out = new int[intCount];
    
    int i = 0;
    for (int j = 0; j < bLen; i += 2)
    {
      r[0] = (bp[j] << 24 | (bp[(j + 1)] & 0xFF) << 16 | (bp[(j + 2)] & 0xFF) << 8 | bp[(j + 3)] & 0xFF);
      r[1] = (bp[(j + 4)] << 24 | (bp[(j + 5)] & 0xFF) << 16 | (bp[(j + 6)] & 0xFF) << 8 | bp[(j + 7)] & 0xFF);
      r = encipher(r);
      out[i] = r[0];
      out[(i + 1)] = r[1];j += 8;
    }
    return out;
  }
  
  public String decode(String cible)
  {
    return new String(decode(hexToBin(cible))).trim();
  }
  
  public byte[] decode(byte[] b, int count)
  {
    int intCount = count / 4;
    int[] ini = new int[intCount];
    
    int i = 0;
    for (int j = 0; i < intCount; j += 8)
    {
      ini[i] = (b[j] << 24 | (b[(j + 1)] & 0xFF) << 16 | (b[(j + 2)] & 0xFF) << 8 | b[(j + 3)] & 0xFF);
      ini[(i + 1)] = (b[(j + 4)] << 24 | (b[(j + 5)] & 0xFF) << 16 | (b[(j + 6)] & 0xFF) << 8 | b[(j + 7)] & 0xFF);i += 2;
    }
    return decode(ini);
  }
  
  public byte[] decode(int[] b)
  {
    int intCount = b.length;
    byte[] outb = new byte[intCount * 4];
    int[] tmp = new int[2];
    
    int j = 0;
    for (int i = 0; i < intCount; j += 8)
    {
      tmp[0] = b[i];
      tmp[1] = b[(i + 1)];
      tmp = decipher(tmp);
      outb[j] = ((byte)(tmp[0] >>> 24));
      outb[(j + 1)] = ((byte)(tmp[0] >>> 16));
      outb[(j + 2)] = ((byte)(tmp[0] >>> 8));
      outb[(j + 3)] = ((byte)tmp[0]);
      outb[(j + 4)] = ((byte)(tmp[1] >>> 24));
      outb[(j + 5)] = ((byte)(tmp[1] >>> 16));
      outb[(j + 6)] = ((byte)(tmp[1] >>> 8));
      outb[(j + 7)] = ((byte)tmp[1]);i += 2;
    }
    return outb;
  }
  
  public int[] hexToBin(String hexStr)
    throws ArrayIndexOutOfBoundsException
  {
    int hexStrLen = hexStr.length();
    if (hexStrLen % 8 != 0) {
      throw new ArrayIndexOutOfBoundsException("Hex string has incorrect length, required to be divisible by eight: " + hexStrLen);
    }
    int outLen = hexStrLen / 8;
    int[] out = new int[outLen];
    byte[] nibble = new byte[2];
    byte[] b = new byte[4];
    int posn = 0;
    for (int i = 0; i < outLen; i++)
    {
      for (int j = 0; j < 4; j++)
      {
        for (int k = 0; k < 2; k++) {
          switch (hexStr.charAt(posn++))
          {
          case '0': 
            nibble[k] = 0;
            break;
          case '1': 
            nibble[k] = 1;
            break;
          case '2': 
            nibble[k] = 2;
            break;
          case '3': 
            nibble[k] = 3;
            break;
          case '4': 
            nibble[k] = 4;
            break;
          case '5': 
            nibble[k] = 5;
            break;
          case '6': 
            nibble[k] = 6;
            break;
          case '7': 
            nibble[k] = 7;
            break;
          case '8': 
            nibble[k] = 8;
            break;
          case '9': 
            nibble[k] = 9;
            break;
          case 'A': 
            nibble[k] = 10;
            break;
          case 'B': 
            nibble[k] = 11;
            break;
          case 'C': 
            nibble[k] = 12;
            break;
          case 'D': 
            nibble[k] = 13;
            break;
          case 'E': 
            nibble[k] = 14;
            break;
          case 'F': 
            nibble[k] = 15;
            break;
          case 'a': 
            nibble[k] = 10;
            break;
          case 'b': 
            nibble[k] = 11;
            break;
          case 'c': 
            nibble[k] = 12;
            break;
          case 'd': 
            nibble[k] = 13;
            break;
          case 'e': 
            nibble[k] = 14;
            break;
          case 'f': 
            nibble[k] = 15;
          }
        }
        b[j] = ((byte)(nibble[0] << 4 | nibble[1]));
      }
      out[i] = (b[0] << 24 | (b[1] & 0xFF) << 16 | (b[2] & 0xFF) << 8 | b[3] & 0xFF);
    }
    return out;
  }
  
  public String binToHex(int[] enc)
    throws ArrayIndexOutOfBoundsException
  {
    if (enc.length % 2 == 1) {
      throw new ArrayIndexOutOfBoundsException("Odd number of ints found: " + enc.length);
    }
    StringBuffer sb = new StringBuffer();
    byte[] outb = new byte[8];
    for (int i = 0; i < enc.length; i += 2)
    {
      outb[0] = ((byte)(enc[i] >>> 24));
      outb[1] = ((byte)(enc[i] >>> 16));
      outb[2] = ((byte)(enc[i] >>> 8));
      outb[3] = ((byte)enc[i]);
      outb[4] = ((byte)(enc[(i + 1)] >>> 24));
      outb[5] = ((byte)(enc[(i + 1)] >>> 16));
      outb[6] = ((byte)(enc[(i + 1)] >>> 8));
      outb[7] = ((byte)enc[(i + 1)]);
      sb.append(getHex(outb));
    }
    return sb.toString();
  }
  
  public String getHex(byte[] b)
  {
    StringBuffer r = new StringBuffer();
    for (int i = 0; i < b.length; i++)
    {
      int c = b[i] >>> 4 & 0xF;
      
      r.append(hex[c]);
      c = b[i] & 0xF;
      r.append(hex[c]);
    }
    return r.toString();
  }
  
  public String padPlaintext(String str, char pc)
  {
    StringBuffer sb = new StringBuffer(str);
    int padding = sb.length() % 9;
    for (int i = 0; i < padding; i++) {
      sb.append(pc);
    }
    return sb.toString();
  }
  
  public String padPlaintext(String str)
  {
    return padPlaintext(str, ' ');
  }
  
  public static byte[] key(String keyString)
  {
    return new BigInteger(keyString, 16).toByteArray();
  }
  public static void main(String[] args)
  {
    teaCrap cypher = new teaCrap(key("0931efbd49644a987d2e0ec945f3646f")); 
	// secret key is md5(teasuck)
//    String expl = "Why do my eyes hurt?";
//    String encoded = cypher.encode(expl);
//    System.out.println("Here you are :" + encoded);
try{
    File file = new File("teaPass.txt");
    String thisLine = null;	
    BufferedReader br = new BufferedReader(new FileReader(file));
    while ((thisLine = br.readLine()) != null) {
    System.out.println(cypher.decode(thisLine));
	}
}catch(IOException e){
e.printStackTrace();
}
}
}
