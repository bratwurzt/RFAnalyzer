package com.mantz_it.rfanalyzer.psk.taximdt;

public class SystemInfo
{
  private String systemName[] = new String[1000];
  private int systemId[] = new int[1000];
  private int index = 0;

  public void addSystemName(String name)
  {
    systemName[index] = name;
  }

  public void addSystemId(String id)
  {
    systemId[index] = Integer.parseInt(id);
  }

  public void increment()
  {
    if (index < 999)
    {
      index++;
    }
  }

  public String nameSearch(int mid)
  {
    int a;
    for (a = 0; a < index; a++)
    {
      if (systemId[a] == mid)
      {
        return systemName[a];
      }
    }
    return null;
  }
}
