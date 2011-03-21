package org.openoffice.helloworld.comp;

import org.apache.commons.math.fraction.Fraction;

import com.sun.star.uno.XComponentContext;
import com.sun.star.lib.uno.helper.Factory;
import com.sun.star.lang.XSingleComponentFactory;
import com.sun.star.registry.XRegistryKey;
import com.sun.star.lib.uno.helper.WeakBase;


public final class HelloworldImpl extends WeakBase
   implements org.openoffice.helloworld.XHelloworld,
              com.sun.star.lang.XServiceInfo
{
    @SuppressWarnings("unused")
	private final XComponentContext m_xContext;
    private static final String m_implementationName = HelloworldImpl.class.getName();
    private static final String[] m_serviceNames = {
        "org.openoffice.helloworld.Helloworld" };
    private String m_LadyName = "";

    public HelloworldImpl( XComponentContext context )
    {
        m_xContext = context;
    };

    public static XSingleComponentFactory __getComponentFactory( String sImplementationName ) {
        XSingleComponentFactory xFactory = null;

        if ( sImplementationName.equals( m_implementationName ) )
            xFactory = Factory.createComponentFactory(HelloworldImpl.class, m_serviceNames);
        return xFactory;
    }

    public static boolean __writeRegistryServiceInfo( XRegistryKey xRegistryKey ) {
        return Factory.writeRegistryServiceInfo(m_implementationName,
                                                m_serviceNames,
                                                xRegistryKey);
    }

    // org.openoffice.helloworld.XHelloworld:
    public String getLadyname()
    {
        return m_LadyName;
    }

    public void setLadyname(String the_value)
    {
    	m_LadyName = the_value;
    }

    public String sayHello(boolean isBadBoy)
    {
        String hello = "Hhh11ello Mrs. " + getLadyname();
        if (isBadBoy) {
        	Fraction f = new Fraction(1, 3);
        	hello = "A third is " + f.doubleValue();
        }
        return hello;
    }

    // com.sun.star.lang.XServiceInfo:
    public String getImplementationName() {
         return m_implementationName;
    }

    public boolean supportsService( String sService ) {
        int len = m_serviceNames.length;

        for( int i=0; i < len; i++) {
            if (sService.equals(m_serviceNames[i]))
                return true;
        }
        return false;
    }

    public String[] getSupportedServiceNames() {
        return m_serviceNames;
    }

}
