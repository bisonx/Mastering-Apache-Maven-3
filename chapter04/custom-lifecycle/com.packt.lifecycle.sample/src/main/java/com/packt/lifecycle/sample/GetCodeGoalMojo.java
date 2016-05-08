package com.packt.lifecycle.sample;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;

/**
 * @goal get-code-goal
 * @requiresProject false
 */
public class GetCodeGoalMojo extends AbstractMojo {

	public void execute() throws MojoExecutionException, MojoFailureException {
		System.out.println("get-code-goal");
	}
}