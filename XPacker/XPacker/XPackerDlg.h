
// XPackerDlg.h: 头文件
//

#pragma once

#include "Packer.h"

// CXPackerDlg 对话框
class CXPackerDlg : public CDialogEx
{
// 构造
public:
	CXPackerDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_XPACKER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	CString m_TargetPE;
	afx_msg void OnBnClickedBtnSelectPe();
	afx_msg void OnBnClickedBtnPacker();
};
