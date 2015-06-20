package com.mantz_it.rfanalyzer.psk.taximdt;

import java.text.DateFormat;
import java.util.Date;

public class DisplayStamp
{

  // Return a date string
  public String getTimestamp()
  {
    String ts;
    Date now = new Date();
    DateFormat df = DateFormat.getTimeInstance();
    ts = df.format(now);
    return ts;
  }
}
