import os
from datetime import datetime
from decimal import Decimal
from typing import List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from app.models import Transaction, Account, User
from app.config import settings


async def generate_account_statement(
    account: Account,
    user: User,
    transactions: List[Transaction],
    start_date: datetime,
    end_date: datetime,
    output_path: str
) -> str:
    """Generate a PDF account statement"""
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=1  # Center
    )
    elements.append(Paragraph("FinCore Account Statement", title_style))
    elements.append(Spacer(1, 20))
    
    # Account Information
    account_info = [
        ["Account Holder:", f"{user.first_name} {user.last_name}"],
        ["Account Number:", account.account_number],
        ["Account Type:", account.account_type.value.title()],
        ["Currency:", account.currency],
        ["Statement Period:", f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"],
        ["Generated On:", datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ["", ""],
        ["Opening Balance:", f"{account.currency} {getattr(transactions[0], 'running_balance', Decimal('0.0000')) if transactions else '0.0000'}" if transactions else f"{account.currency} 0.0000"],
        ["Closing Balance:", f"{account.currency} {account.current_balance}"],
    ]
    
    account_table = Table(account_info, colWidths=[2.5*inch, 3.5*inch])
    account_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, -3), (-1, -3), 1, colors.black),
    ]))
    elements.append(account_table)
    elements.append(Spacer(1, 30))
    
    # Transaction Table
    if transactions:
        elements.append(Paragraph("Transaction History", styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        # Table header and data
        txn_data = [
            ["Date", "Reference", "Description", "Type", "Amount", "Balance"]
        ]
        
        running_balance = Decimal('0.0000')
        if transactions:
            # Calculate opening balance
            total_debits = sum(t.amount for t in transactions if t.transaction_type.value in ['withdrawal', 'transfer'] and t.from_account_id == account.id)
            total_credits = sum(t.amount for t in transactions if t.transaction_type.value in ['deposit', 'transfer'] and t.to_account_id == account.id)
            running_balance = account.current_balance - total_credits + total_debits
        
        for txn in transactions:
            # Determine debit/credit for this account's perspective
            if txn.from_account_id == account.id:
                amount_str = f"-{txn.amount}"
                if txn.transaction_type.value == 'transfer':
                    running_balance -= txn.amount
                else:
                    running_balance -= txn.amount
            elif txn.to_account_id == account.id:
                amount_str = f"+{txn.amount}"
                if txn.transaction_type.value == 'transfer':
                    running_balance += txn.amount
                else:
                    running_balance += txn.amount
            else:
                amount_str = str(txn.amount)
            
            txn_data.append([
                txn.created_at.strftime('%Y-%m-%d'),
                txn.transaction_reference[:12],
                (txn.description or '')[:25],
                txn.transaction_type.value.title(),
                f"{account.currency} {amount_str}",
                f"{account.currency} {running_balance}"
            ])
        
        txn_table = Table(txn_data, colWidths=[0.9*inch, 1.0*inch, 1.8*inch, 0.8*inch, 1.0*inch, 1.0*inch])
        txn_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            ('ALIGN', (4, 1), (-1, -1), 'RIGHT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        elements.append(txn_table)
    else:
        elements.append(Paragraph("No transactions during this period.", styles['Normal']))
    
    elements.append(Spacer(1, 30))
    
    # Footer
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey
    )
    elements.append(Paragraph(
        "This statement is generated by FinCore. For questions, contact support@fincore.local",
        footer_style
    ))
    
    # Build PDF
    doc.build(elements)
    
    return output_path
