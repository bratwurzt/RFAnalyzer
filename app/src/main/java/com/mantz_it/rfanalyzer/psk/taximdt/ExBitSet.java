package com.mantz_it.rfanalyzer.psk.taximdt;

import java.util.BitSet;

// A special extension of the BitSet class that adds a number of special methods
public class ExBitSet extends BitSet
{
  public static final long serialVersionUID = 1;
  private int bitCount = 0;

  //getters
  public int getBitCount()
  {
    return bitCount;
  }

  // Convert a BitSet to a String showing binary info e.g "1010"
  public String convertToString(int start, int end)
  {
    String ret = "";

    for (int a = start; a < end; a++)
    {
      if (this.get(a) == true)
      {
        ret = ret + "1";
      }
      else
      {
        ret = ret + "0";
      }
    }

    return ret;
  }

  // Unstuff a BitSet
  public ExBitSet unstuff(int brxed)
  {
    ExBitSet ustuff = new ExBitSet();
    bitCount = 5;

    // The first 5 bits can be copied directly //
    for (int i = 0; i < 5; i++)
    {
      ustuff.set(i, this.get(i));
    }

    // Now we have enough bits to hunt for the special sequence //
    for (int i = 5; i <= (brxed - 9); i++)
    {
      // Look for 111110 //
      if ((this.get(i) == false) && (this.get(i - 1) == true)
          && (this.get(i - 2) == true) && (this.get(i - 3) == true)
          && (this.get(i - 4) == true) && (this.get(i - 5) == true))
      {
        // TODO : Tidy up this crufty code
      }
      else
      {
        ustuff.set(bitCount, this.get(i));
        bitCount++;
      }
    }

    return ustuff;
  }
}
