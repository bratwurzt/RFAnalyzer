package com.mantz_it.rfanalyzer.psk.taximdt;

/**
 * @author bratwurzt
 */
public class TaxiMdt
{
  public int whichChannel;
  private double i0[] = new double[18];
  private double i1[] = new double[18];
  private double q0[] = new double[18];
  private double q1[] = new double[18];
  private double sum[] = new double[4];
  private double corr_i0[] = new double[9];
  private double corr_q0[] = new double[9];
  private double corr_i1[] = new double[9];
  private double corr_q1[] = new double[9];
  private int currSample = 0;
  private int pll = 9;
  private int corr = 0;
  private int nufOnes = 0;
  public boolean syncHunt = false;
  public boolean preambleHunt = false;
  public boolean decodeMode = true;
  public ExBitSet rawBits = new ExBitSet();

  public long syncRxed = 0;
  public long preambleRxed = 0;
  public byte preambleHuntStatus = 0;
  public int bitsRxed = -1;

  public int messageHandled = 0;
  public int messageLength = 0;

  public SystemInfo info = new SystemInfo();
  TaxiMdtDecoder packetDecoder;

  public TaxiMdt()
  {
    packetDecoder = new TaxiMdtDecoder(info);

    //set all vars
    int i;
    for (i = 0; i < 18; i++)
    {
      // 1800 Hz //
      // 1800/1200 = 1.5 //
      i0[i] = Math.sin(2.0 * Math.PI * ((double)i / 9) * 1.5);
      q0[i] = Math.cos(2.0 * Math.PI * ((double)i / 9) * 1.5);
      // 1200 Hz //
      // 1200/1200 = 1.0 //
      i1[i] = Math.sin(2.0 * Math.PI * ((double)i / 9) * 1.0);
      q1[i] = Math.cos(2.0 * Math.PI * ((double)i / 9) * 1.0);
    }
    // Clear the sum variable array //
    sum[0] = 0.0;
    sum[1] = 0.0;
    sum[2] = 0.0;
    sum[3] = 0.0;
  }

  /**
   * Process the raw audio received
   *
   * @param bytes
   * @param audioBuffer
   */
  public void processAudio(int bytes, byte[] audioBuffer)
  {
    int i;
    double sample, abs_sum, average = 0;
    // Run through each byte in the buffer
    for (i = 0; i < bytes; i++)
    {
      sample = ((double)audioBuffer[i] - 8.0) / 8.0;
      sum[0] = sum[0] - corr_i0[currSample % 9];
      sum[1] = sum[1] - corr_q0[currSample % 9];
      sum[2] = sum[2] - corr_i1[currSample % 9];
      sum[3] = sum[3] - corr_q1[currSample % 9];
      corr_i0[currSample % 9] = i0[currSample] * sample;
      corr_q0[currSample % 9] = q0[currSample] * sample;
      corr_i1[currSample % 9] = i1[currSample] * sample;
      corr_q1[currSample % 9] = q1[currSample] * sample;
      sum[0] = sum[0] + corr_i0[currSample % 9];
      sum[1] = sum[1] + corr_q0[currSample % 9];
      sum[2] = sum[2] + corr_i1[currSample % 9];
      sum[3] = sum[3] + corr_q1[currSample % 9];
      currSample++;
      currSample = currSample % 18;
      // Ones calc mask = 256
      if ((corr & 256) == 256)
      {
        nufOnes--;
      }
      corr <<= 1;
      // Ensure corr doesn't overflow and change sign
      corr = corr & 0xffff;
      abs_sum = Math.sqrt(sum[2] * sum[2] + sum[3] * sum[3])
          - Math.sqrt(sum[0] * sum[0] + sum[1] * sum[1]);
      // Add the sample to an average
      average = average + Math.abs(sample);
      if (abs_sum > 0.0)
      {
        corr++;
        nufOnes++;
      }
      pll--;
      if (pll == 0)
      {
        pll = symbolRecovery();
      }
    }
    // Calculate the average
    average = average / bytes;
    // Set the volume progress bar indicator //
    //theApp.updateVolumeBar(whichChannel, average); todo
  }

  /**
   * Demodulate the audio received
   *
   * @return
   */
  public int symbolRecovery()
  {
    int diff = 0;
    boolean bit;
    // 0 or 1
    if (nufOnes > 4)
    {
      bit = true;
    }
    else
    {
      bit = false;
    }

    if (syncHunt)
    {
      syncHunt(bit);
    }
    if (preambleHunt)
    {
      preambleCheck(bit);
    }
    if (decodeMode)
    {
      packetDecoder.decode(bit, whichChannel);
    }

    // Early Late Gate //
    if (nufOnes > 4)
    {
      if ((corr & 0x0028) != 0x0028)
      {
        if ((corr & 0x0008) != 0)
        {
          diff = 3;
        }
        else
        {
          diff = -3;
        }
      }
      else if ((corr & 0x0044) != 0x0044)
      {
        if ((corr & 0x0004) != 0)
        {
          diff = 2;
        }
        else
        {
          diff = -2;
        }
      }
      else if ((corr & 0x0082) != 0x0082)
      {
        if ((corr & 0x0002) != 0)
        {
          diff = 1;
        }
        else
        {
          diff = -1;
        }
      }
      else if ((corr & 0x0101) != 0x0101)
      {
        diff = 0;
      }
      else
      {
        diff = 0;
      }
    }
    return diff + 9;
  }

  /**
   * Hunt for and display sync sequences
   *
   * @param in
   */
  public void syncHunt(boolean in)
  {
    long check_pre;
    // Rotate the preamble word 1 bit to the left
    preambleRxed <<= 1;
    // We only need 31 bits of this
    preambleRxed = preambleRxed & 0xffffffffL;
    // Add the latest bit
    if (in)
    {
      preambleRxed++;
    }
    // The program is looking for the high 16 bits to be alternating 1's and
    // 0's (0xaa)
    // But the lower 16 bits being different
    check_pre = preambleRxed & 0xffff0000L;
    if (check_pre == 0xaaaa0000L)
    {
      long high_sync = preambleRxed & 0xff00;
      high_sync = high_sync >> 8;
      // Check this high byte doesn't start 1010101
      if ((high_sync & 0xfe) == 0x55)
      {
        return;
      }
      // Check this high byte doesn't start 101010
      if ((high_sync & 0x3f) == 0x2a)
      {
        return;
      }
      // Check this high byte doesn't start 1010
      if ((high_sync & 0xf0) == 0xa0)
      {
        return;
      }
      // Check this high byte doesn't start 10
      if ((high_sync & 0xc0) == 0x80)
      {
        return;
      }
      long low_sync = preambleRxed & 0xff;
      if ((high_sync != 0xaa) && (low_sync != 0xaa))
      {
        String line = "SYNC 0x";
        // Thats it the lower 16 bits is the sync word
        preambleRxed = preambleRxed & 0xffff;
        line = line + Integer.toHexString((int)preambleRxed);
        // Display this
        //theApp.addLine(line, whichChannel); todo
        preambleRxed = 0;
      }
    }
  }

  /**
   * Look for 16 bits of preamble then display the following 64 bits This aids diagnostics
   *
   * @param in
   */
  public void preambleCheck(boolean in)
  {
    // If preamble_hunt_status==0 we are looking for the alternating
    // sequence
    if (preambleHuntStatus == 0)
    {
      // Rotate the premable holder 1 bit to the left
      preambleRxed <<= 1;
      // We only need 16 bits of this
      preambleRxed = preambleRxed & 0xffff;
      // Add the received bit
      if (in)
      {
        preambleRxed++;
      }
      // Have we received 1010101010101010
      if (preambleRxed == 0xaaaa)
      {
        preambleHuntStatus = 1;
      }
      return;
    }
    // If preamble_hunt_status==1 we are hunting for data
    if (preambleHuntStatus == 1)
    {
      int i;
      // Rotate the raw data buffer once to the left //
      for (i = 255; i > 0; i--)
      {
        rawBits.set(i, rawBits.get(i - 1));
      }
      rawBits.set(0, in);
      // Increment the received bits counter
      bitsRxed++;
      // If we have received 64 bits then that is enough
      if (bitsRxed == 64)
      {
        String dline = "P ";
        for (i = 63; i > -1; i--)
        {
          if (rawBits.get(i))
          {
            dline = dline + "1";
          }
          else
          {
            dline = dline + "0";
          }
        }
        //theApp.addLine(dline, whichChannel); todo
        // Clear the preamble hunt variables
        preambleHuntStatus = 0;
        bitsRxed = 0;
        preambleRxed = 0;
      }
    }
  }

  /**
   * Clear assorted variables so the program is ready for the next message
   */
  public void clearReadyForNextMsg()
  {
    messageLength = 0;
    messageHandled = 0;
    bitsRxed = -1;
    preambleHuntStatus = 0;
    if (rawBits != null)
    {
      rawBits.clear();
    }
  }
}
