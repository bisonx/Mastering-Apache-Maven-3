package com.packt.samples.axis2.handler;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for SampleAxis2Handler.
 */
public class SampleAxis2HandlerTest extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public SampleAxis2HandlerTest( String testName )
    {
       super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
       return new TestSuite(SampleAxis2HandlerTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testHandler()
    {
       assertTrue( true );
    }

}
