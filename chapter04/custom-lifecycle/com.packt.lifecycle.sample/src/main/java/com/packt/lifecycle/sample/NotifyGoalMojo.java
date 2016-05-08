package com.packt.lifecycle.sample;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;

/**
 * @goal notify-goal
 * @requiresProject false
 */
public class NotifyGoalMojo extends AbstractMojo {

	public void execute() throws MojoExecutionException, MojoFailureException {
		System.out.println("notify-goal");
	}
}