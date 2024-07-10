
// XPackerDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "XPacker.h"
#include "XPackerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CXPackerDlg 对话框



CXPackerDlg::CXPackerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_XPACKER_DIALOG, pParent)
	, m_TargetPE(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CXPackerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_TARGET_PE, m_TargetPE);
}

BEGIN_MESSAGE_MAP(CXPackerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CXPackerDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BTN_SELECT_PE, &CXPackerDlg::OnBnClickedBtnSelectPe)
	ON_BN_CLICKED(ID_BTN_PACKER, &CXPackerDlg::OnBnClickedBtnPacker)
END_MESSAGE_MAP()


// CXPackerDlg 消息处理程序

BOOL CXPackerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CXPackerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CXPackerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CXPackerDlg::OnBnClickedOk()
{
	
}


void CXPackerDlg::OnBnClickedBtnSelectPe()
{
	CFileDialog fileDlg(true);
	if (fileDlg.DoModal()==IDOK) 
	{
		m_TargetPE = fileDlg.GetPathName();
		UpdateData(false);
	}
}


void CXPackerDlg::OnBnClickedBtnPacker()
{
	UpdateData(true);

	if (m_TargetPE.IsEmpty()) {
		AfxMessageBox("请选择需要加壳的PE文件");
	}

	char dllName[100] = { 0 };
	::GetModuleFileNameA(NULL, dllName,100);

	Packer packer;
	if (packer.Pack(m_TargetPE) == true)
	{
		AfxMessageBox("加壳成功");
	}
	else
	{
		AfxMessageBox("加壳失败");
	}
}
