package com.packt.lifecycle.ext;

import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenSession;
import org.codehaus.plexus.component.annotations.Component;

@Component(role = AbstractMavenLifecycleParticipant.class, hint = "packt")
public class PACKTLifeCycleExtension extends AbstractMavenLifecycleParticipant {

	@Override
	public void afterProjectsRead(MavenSession session) {
		System.out.println("All Maven project instances are created.");
		System.out.println("Offline building: " + session.isOffline());
	}

	@Override
	public void afterSessionEnd(MavenSession session) throws MavenExecutionException {
		System.out.println("All Maven projects are built.");
	}
}