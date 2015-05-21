package burp.xxser.bin;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;

public class TreeUtil {
	/**
	 * 删除所有节点
	 * @param tree
	 */
	public static void removeAll(JTree  tree){
		
		DefaultTreeModel  model =	(DefaultTreeModel) tree.getModel();
		
		DefaultMutableTreeNode root = (DefaultMutableTreeNode) model.getRoot();
		
		root.removeAllChildren();
		
		model.reload();
		
	}
	
	/**
	 * 设置图标什么的为空
	 */
	public static void setImage(JTree tree){
		DefaultTreeCellRenderer  renderer =	(DefaultTreeCellRenderer) tree.getCellRenderer();
		renderer.setLeafIcon(null); //设置叶子节点图标为空
    	renderer.setClosedIcon(null);  //设置关闭节点的图标为空
    	renderer.setOpenIcon(null); //设置打开节点的图标为空
    	tree.updateUI();
	}
	
}
