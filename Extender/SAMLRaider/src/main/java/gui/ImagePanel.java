package gui;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.JPanel;

public class ImagePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private BufferedImage image;
	private int preferredHeight = 1200;
	private int preferredWidth = 800;

	public ImagePanel(String path) {
		try {
			image = ImageIO.read(new File(path));
		} catch (IOException ex) {
			try {
				image = ImageIO.read(getClass().getResourceAsStream("/" + path));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		BufferedImage resized = new BufferedImage(preferredWidth, preferredHeight, image.getType());
		Graphics2D g = resized.createGraphics();
		g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
		g.drawImage(image, 0, 0, preferredWidth, preferredHeight, 0, 0, image.getWidth(), image.getHeight(), null);
		g.dispose();
		image = resized;
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		g.drawImage(image, 0, 0, null);
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(preferredWidth, preferredHeight);

	}
}